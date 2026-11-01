//! rcmd.rs without the network: `.rhosts` matching (validuser), `ruserpass` on a private ~/.netrc and `rresvport_af`
//! (not root: the bind fails), printed to a transcript that must not change across the U2 conversion.
use crate::rcmd::*;
use core::ffi::c_char;
use std::ffi::CStr;
use std::fmt::Write;

pub(crate) fn transcript() -> String {
    let _etc = crate::tests::EtcGuard::with_files(&[("netgroup", "ng1 (localhost,alice,) (,bob,)\nng2 (otherhost,,)\n"), ("nsswitch.conf", "hosts: files\nnetgroup: files\n")]);
    let mut o = String::new();
    let mut v4 = [0u8; 16];
    v4[..2].copy_from_slice(&2u16.to_ne_bytes());
    v4[4..8].copy_from_slice(&[127, 0, 0, 1]);
    let mut v6 = [0u8; 28];
    v6[..2].copy_from_slice(&10u16.to_ne_bytes());
    v6[23] = 1;
    let texts = [
        "", "# only a comment\n", "+\n", "+ +\n", "localhost\n", "LOCALHOST alice\n", "127.0.0.1 bob\n", "127.0.0.2 bob\n", "-localhost\n+\n",
        "localhost -alice\nlocalhost\n", "+@ng1 alice\n", "+@ng1 +@ng1\n", "-@ng2\n+ +\n", "localhost +@ng1\n", "localhost -@ng1\n+ +\n",
        "::1 alice\n", "  \t\nlocalhost\talice\n", "nosuchhost.invalid alice\nlocalhost alice", "localhost alice extra words\n", "\n\n+ -bob\n+ +\n",
        "-\n+\n", "localhost   \n",
    ];
    for t in texts {
        for (ra, ralen) in [(&v4[..], 16u32), (&v6[..], 28)] {
            for (lu, ru, rh) in [(c"alice", c"alice", c"localhost"), (c"alice", c"bob", c"-"), (c"carol", c"bob", c"localhost"), (c"bob", c"bob", c"otherhost")] {
                let r = unsafe { validuser(t.as_bytes(), ra.as_ptr().cast(), ralen, lu.as_ptr(), ru.as_ptr(), rh.as_ptr()) };
                writeln!(o, "{t:?} {ralen} {lu:?} {ru:?} {rh:?} -> {r:?}").unwrap();
            }
        }
    }
    // ruserpass on a private HOME
    let home = std::env::temp_dir().join(format!("libc-net-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let old_home = std::env::var_os("HOME");
    unsafe { std::env::set_var("HOME", &home) };
    let netrcs = [
        "machine example.com login joe password secret\n",
        "machine other.org login x\ndefault login anonymous password guest\n",
        "machine \"example.com\" login \"j\\\"q\" account a macdef m\n",
        "machine example.com login joe\nmachine example.com login sue password p2\n",
        "machine example.com bogus word login z\n",
    ];
    for (k, text) in netrcs.iter().enumerate() {
        let p = home.join(".netrc");
        std::fs::write(&p, text).unwrap();
        for mode in [0o600, 0o644] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            for pre in [None, Some(c"joe"), Some(c"anonymous")] {
                let mut name: *const c_char = pre.map_or(core::ptr::null(), |c| c.as_ptr());
                let mut pass: *const c_char = core::ptr::null();
                let r = unsafe { ruserpass(c"example.com".as_ptr(), &mut name, &mut pass) };
                let sh = |p: *const c_char| if p.is_null() { "NULL".to_string() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() };
                writeln!(o, "netrc {k} {mode:o} {pre:?} -> {r} {} {}", sh(name), sh(pass)).unwrap();
            }
        }
    }
    std::fs::remove_file(home.join(".netrc")).unwrap();
    let mut name: *const c_char = core::ptr::null();
    let mut pass: *const c_char = core::ptr::null();
    writeln!(o, "no netrc -> {}", unsafe { ruserpass(c"example.com".as_ptr(), &mut name, &mut pass) }).unwrap();
    match old_home {
        Some(h) => unsafe { std::env::set_var("HOME", h) },
        None => unsafe { std::env::remove_var("HOME") },
    }
    let _ = std::fs::remove_dir_all(&home);
    // rresvport_af: not root, so every reserved port is refused (EACCES on the first bind)
    for (port, fam) in [(1023, 2u16), (100, 2), (5000, 10), (600, 1)] {
        let mut p = port;
        let s = unsafe { rresvport_af(&mut p, fam) };
        let e = rusty_libc_core::errno::get();
        if s >= 0 {
            let _ = rusty_libc_core::unistd::close(s);
        }
        writeln!(o, "rresvport_af({port},{fam}) -> {} port {p} errno {e}", (s >= 0) as i32).unwrap();
    }
    o
}

#[test]
fn rcmd_transcript_unchanged() {
    let _l = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = transcript();
    let mut hsh: u64 = 0xcbf29ce484222325;
    for b in t.bytes() {
        hsh = (hsh ^ b as u64).wrapping_mul(0x100000001b3);
    }
    if let Some(p) = std::env::var_os("RCMD_DUMP") {
        std::fs::write(p, &t).unwrap();
    }
    assert_eq!((t.len(), hsh), (EXPECT_LEN, EXPECT_HASH), "{t}");
}

const EXPECT_LEN: usize = 11327;
const EXPECT_HASH: u64 = 390636101188108449;
