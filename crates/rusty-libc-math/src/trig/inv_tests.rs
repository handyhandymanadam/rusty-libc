//! Audit of the atan, asin, acos kernels of inv.rs against MPFR.
use super::inv;
use crate::testkit::audit::audit;
use crate::testkit::inputs::Domain;

const NA: u64 = 300_000;
const TINY: f64 = 1.0 / (1u64 << 27) as f64;

#[test]
fn inverse_kernel_bounds() {
    let unit_doms = [
        Domain::new(-1.0, 1.0),
        Domain::new(-0.5, 0.5),
        Domain::new(0.4, 0.6),
        Domain::new(0.9, 0.999999),
        Domain::new(0.999999, 1.0),
        Domain::new(-1.0, -0.4),
        Domain::new(1e-9, 1e-3),
    ];
    for dom in unit_doms {
        let ok = |x: f64| x.abs() >= TINY && x.abs() < 1.0;
        let ok2 = |x: f64| ok(x) && x.abs() >= 2f64.powi(-60);
        for (fma, n) in [(true, NA), (false, NA / 4)] {
            let (a, c) = if fma {
                (
                    audit("asin", dom, n, 21, |x| if ok(x) { Some(inv::asin_pair::<true>(x)) } else { None }),
                    audit("acos", dom, n, 22, |x| if ok2(x) { Some(inv::acos_pair::<true>(x)) } else { None }),
                )
            } else {
                (
                    audit("asin", dom, n, 21, |x| if ok(x) { Some(inv::asin_pair::<false>(x)) } else { None }),
                    audit("acos", dom, n, 22, |x| if ok2(x) { Some(inv::acos_pair::<false>(x)) } else { None }),
                )
            };
            println!("fma={fma} {:?}:\n  asin {a}\n  acos {c}", (dom.lo, dom.hi));
            assert!(a.within(inv::E_INV), "asin {a}");
            assert!(c.within(inv::E_INV), "acos {c}");
        }
    }
    for dom in [Domain::new(-5.0, 5.0), Domain::new(0.9, 1.1), Domain::new(1e-9, 1e-2), Domain::all(), Domain::new(-1e18, 1e18)] {
        let ok = |x: f64| x.abs() >= TINY;
        let a = audit("atan", dom, NA, 23, |x| if ok(x) { Some(inv::atan_pair::<true>(x)) } else { None });
        println!("atan fma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(inv::E_INV), "atan {a}");
        let a = audit("atan", dom, NA / 4, 24, |x| if ok(x) { Some(inv::atan_pair::<false>(x)) } else { None });
        println!("atan nofma {:?}: {a}", (dom.lo, dom.hi));
        assert!(a.within(inv::E_INV), "atan {a}");
    }
}
