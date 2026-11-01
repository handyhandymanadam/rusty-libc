//! Netgroups on a private etc directory: the cases of tests/c/netgroup_diff.c (without the nis lines), printed to a text
//! that must not change (U2 conversion check: the text is compared with the one the code before U2 gave).
use crate::netgrp::*;
use core::ffi::c_char;
use std::ffi::{CStr, CString};
use std::fmt::Write;

fn s(p: *const c_char) -> String {
    if p.is_null() { "NULL".into() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

pub(crate) fn transcript() -> String {
    let mut text = String::from(concat!(
        "# comment line\n", "simple (host1,user1,dom1) (host2,user2,dom2)\n", "spaces ( host3 , user3 , dom3 ) (  ,  ,  )\n",
        "empty () (,,) (a,,) (,b,) (,,c)\n", "any (,,)\n", "nested simple spaces (hostN,userN,domN)\n", "loop1 (l1h,l1u,l1d) loop2\n",
        "loop2 (l2h,l2u,l2d) loop1 loop2\n", "self (sh,su,sd) self\n", "cont (c1h,c1u,c1d) \\\n", "      (c2h,c2u,c2d) \\\n",
        "      nested\n", "contbad (b1,b1,b1) \\\n", "(b2,b2,b2)\\\n", "(b3,b3,b3)\n", "tabs\t(t1,t1,t1)\t(t2,t2,t2)\n",
        "case (HostA,UserA,DomA)\n", "mixed (host1,user1,dom1) (HOST1,USER1,DOM1)\n", "bad (ok,ok,ok) (broken,only,two\n",
        "bad2 (x,y z,w) (nocomma) (q,r,s)\n", "toplevel simple nested loop1 missinggroup\n", "longone"
    ));
    for i in 0..120 {
        write!(text, " (a{i},b{i},c{i})").unwrap();
    }
    text.push_str("\nlast (lh,lu,ld)");
    let _etc = crate::tests::EtcGuard::with_files(&[("netgroup", &text), ("nsswitch.conf", "hosts: files\nnetgroup: files\n")]);
    let mut o = String::new();
    let (mut h, mut u, mut d) = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
    unsafe {
        for g in ["simple", "spaces", "empty", "any", "nested", "loop1", "loop2", "self", "cont", "contbad", "tabs", "case", "mixed", "bad", "bad2", "toplevel", "longone", "last", "nosuchgroup", "simpl", "simple2", "", "#", "comment"] {
            let c = CString::new(g).unwrap();
            writeln!(o, "group {g} set {}", setnetgrent(c.as_ptr())).unwrap();
            let mut n = 0;
            while n < 60 && getnetgrent(&mut h, &mut u, &mut d) == 1 {
                writeln!(o, "  ({},{},{})", s(h), s(u), s(d)).unwrap();
                n += 1;
            }
            endnetgrent();
        }
        for size in [0usize, 4, 12, 20, 40, 100, 1000] {
            for g in [c"simple", c"nested"] {
                let mut buf = vec![0u8; size + 1];
                writeln!(o, "group_r {g:?} {size} set {}", setnetgrent(g.as_ptr())).unwrap();
                let (mut n, mut fails) = (0, 0);
                while n < 40 && fails < 3 {
                    *rusty_libc_core::errno::location() = 0;
                    if getnetgrent_r(&mut h, &mut u, &mut d, buf.as_mut_ptr().cast(), size) == 1 {
                        writeln!(o, "  ({},{},{})", s(h), s(u), s(d)).unwrap();
                        n += 1;
                        fails = 0;
                    } else {
                        writeln!(o, "  0 errno {}", rusty_libc_core::errno::get()).unwrap();
                        fails += 1;
                    }
                }
                endnetgrent();
            }
        }
        endnetgrent();
        writeln!(o, "no group {}", getnetgrent(&mut h, &mut u, &mut d)).unwrap();
        setnetgrent(c"simple".as_ptr());
        getnetgrent(&mut h, &mut u, &mut d);
        writeln!(o, "first ({},{},{})", s(h), s(u), s(d)).unwrap();
        setnetgrent(c"empty".as_ptr());
        getnetgrent(&mut h, &mut u, &mut d);
        writeln!(o, "first of empty ({},{},{})", s(h), s(u), s(d)).unwrap();
        endnetgrent();
        writeln!(o, "after end {}", getnetgrent(&mut h, &mut u, &mut d)).unwrap();
        let q = |x: Option<&str>| x.map(|x| CString::new(x).unwrap());
        let cases: &[(&str, Option<&str>, Option<&str>, Option<&str>)] = &[
            ("simple", Some("host1"), Some("user1"), Some("dom1")), ("simple", Some("HOST1"), Some("user1"), Some("DOM1")),
            ("simple", Some("host1"), Some("USER1"), Some("dom1")), ("simple", Some("host1"), None, None), ("simple", None, Some("user2"), None),
            ("simple", None, None, Some("dom2")), ("simple", None, None, None), ("simple", Some("host1"), Some("user2"), Some("dom1")),
            ("simple", Some("host9"), None, None), ("spaces", Some("host3"), Some("user3"), Some("dom3")), ("spaces", Some("anything"), Some("anyone"), Some("anydom")),
            ("empty", Some("a"), Some("w"), Some("w")), ("empty", Some("x"), Some("b"), Some("x")), ("empty", Some("x"), Some("y"), Some("c")),
            ("any", Some("q"), Some("r"), Some("s")), ("nested", Some("host2"), Some("user2"), Some("dom2")), ("nested", Some("hostN"), Some("userN"), Some("domN")),
            ("nested", Some("host3"), Some("user3"), Some("dom3")), ("nested", Some("nowhere"), Some("nobody"), Some("nodom")), ("loop1", Some("l2h"), Some("l2u"), Some("l2d")),
            ("loop2", Some("l1h"), Some("l1u"), Some("l1d")), ("loop1", Some("none"), Some("none"), Some("none")), ("self", Some("sh"), Some("su"), Some("sd")),
            ("self", Some("x"), Some("y"), Some("z")), ("cont", Some("c2h"), Some("c2u"), Some("c2d")), ("cont", Some("host1"), Some("user1"), Some("dom1")),
            ("contbad", Some("b2"), Some("b2"), Some("b2")), ("contbad", Some("b3"), Some("b3"), Some("b3")), ("case", Some("hosta"), Some("usera"), Some("doma")),
            ("case", Some("hosta"), Some("UserA"), Some("doma")), ("mixed", Some("host1"), Some("USER1"), Some("dom1")), ("bad", Some("ok"), Some("ok"), Some("ok")),
            ("bad", Some("broken"), Some("only"), Some("two")), ("bad2", Some("q"), Some("r"), Some("s")), ("toplevel", Some("l2h"), Some("l2u"), Some("l2d")),
            ("toplevel", Some("sh"), Some("su"), Some("sd")), ("longone", Some("a119"), Some("b119"), Some("c119")), ("longone", Some("a0"), Some("b0"), Some("c0")),
            ("longone", Some("a120"), None, None), ("last", Some("lh"), Some("lu"), Some("ld")), ("nosuchgroup", Some("x"), Some("y"), Some("z")),
            ("", Some("x"), Some("y"), Some("z")), ("simple", Some(""), Some(""), Some("")), ("simple", Some("host1"), Some(""), Some("")),
        ];
        for (g, a, b, c) in cases {
            let (gc, ac, bc, cc) = (CString::new(*g).unwrap(), q(*a), q(*b), q(*c));
            let p = |x: &Option<CString>| x.as_ref().map_or(core::ptr::null(), |x| x.as_ptr());
            writeln!(o, "innetgr({g},{a:?},{b:?},{c:?}) = {}", innetgr(gc.as_ptr(), p(&ac), p(&bc), p(&cc))).unwrap();
        }
    }
    o
}

#[test]
fn netgroup_transcript_unchanged() {
    let _l = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = transcript();
    // the transcript of the code before the U2 conversion, kept by its hash (FNV-1a 64) and length
    let mut hsh: u64 = 0xcbf29ce484222325;
    for b in t.bytes() {
        hsh = (hsh ^ b as u64).wrapping_mul(0x100000001b3);
    }
    if std::env::var_os("NETGRP_DUMP").is_some() {
        std::fs::write(std::env::var("NETGRP_DUMP").unwrap(), &t).unwrap();
    }
    assert!(t.contains("innetgr(simple,Some(\"host1\"),Some(\"user1\"),Some(\"dom1\")) = 1"), "{t}");
    assert_eq!((t.len(), hsh), (EXPECT_LEN, EXPECT_HASH), "{t}");
}

const EXPECT_LEN: usize = 5990;
const EXPECT_HASH: u64 = 12500566479954922388;
