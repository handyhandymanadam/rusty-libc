//! Host tests for mntent.rs: the same files are read and written with our functions and with the host
//! glibc's; every field of every entry (and the bytes addmntent writes) must be equal.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::mntent::{self, Mntent};
use std::ffi::{CStr, CString, c_char, c_int, c_void};

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn setmntent(file: *const c_char, mode: *const c_char) -> *mut c_void;
        pub fn endmntent(f: *mut c_void) -> c_int;
        pub fn getmntent_r(f: *mut c_void, m: *mut Mntent, buf: *mut c_char, size: c_int) -> *mut Mntent;
        pub fn getmntent(f: *mut c_void) -> *mut Mntent;
        pub fn addmntent(f: *mut c_void, m: *const Mntent) -> c_int;
        pub fn hasmntopt(m: *const Mntent, opt: *const c_char) -> *mut c_char;
        pub fn feof(f: *mut c_void) -> c_int;
    }
}

type Row = (String, String, String, String, i32, i32);

fn row(m: &Mntent) -> Row {
    let s = |p: *const c_char| unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() };
    (s(m.mnt_fsname), s(m.mnt_dir), s(m.mnt_type), s(m.mnt_opts), m.mnt_freq, m.mnt_passno)
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("extra-mntent-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn read_host(path: &str, bufsize: c_int) -> Vec<Row> {
    unsafe {
        let p = CString::new(path).unwrap();
        let f = host::setmntent(p.as_ptr(), c"r".as_ptr());
        if f.is_null() {
            return vec![];
        }
        let mut out = vec![];
        let mut m: Mntent = std::mem::zeroed();
        let mut buf = vec![0 as c_char; 16384];
        loop {
            let r = host::getmntent_r(f, &mut m, buf.as_mut_ptr(), bufsize);
            if r.is_null() {
                break;
            }
            out.push(row(&*r));
            // a reader that never reaches the end fails the test instead of spinning
            assert!(out.len() < 100_000, "getmntent_r does not reach the end of the file");
        }
        host::endmntent(f);
        out
    }
}

fn read_ours(path: &str, bufsize: c_int) -> Vec<Row> {
    unsafe {
        let p = CString::new(path).unwrap();
        let f = mntent::setmntent(p.as_ptr(), c"r".as_ptr());
        if f.is_null() {
            return vec![];
        }
        let mut out = vec![];
        let mut m: Mntent = std::mem::zeroed();
        let mut buf = vec![0 as c_char; 16384];
        loop {
            let r = mntent::getmntent_r(f, &mut m, buf.as_mut_ptr(), bufsize);
            if r.is_null() {
                break;
            }
            out.push(row(&*r));
            // a reader that never reaches the end fails the test instead of spinning
            assert!(out.len() < 100_000, "getmntent_r does not reach the end of the file");
        }
        mntent::endmntent(f);
        out
    }
}

const TAB: &str = "# a comment\n\n   \t  \n   # indented comment\n\
/dev/sda1 / ext4 rw,relatime 0 1\n\
/dev/disk/by-label/My\\040Disk /mnt/my\\040disk vfat noauto,user 0 0\n\
tab\\011sep /a\\012b ext4 defaults 1 2\n\
back\\134slash /c\\\\d ext4 defaults 3 4\n\
only-fsname\ntwo fields\nthree fields here\nfour fields here opts\nfive fields here opts 7\nsix fields here opts 8 9\n\
seven fields here opts 8 9 extra junk\ntabs\tbetween\tfields\tdefaults\t5\t6\ntrailing blanks / ext4 rw 1 2   \t \n\
x y z w abc def\nx y z w 12abc\nx y z w -3 -4\nx y z w 99999999999 99999999999\nx y z w 0x10 010\n\
auto /misc autofs ignore,indirect 0 0\nauto2 /misc2 autofs indirect,ignore=x 0 0\nauto3 /misc3 autofs indirect 0 0\n\
nfs:/exp /n nfs rw,ignore 0 0\nesc\\04 short\\ \\0401 \\040\\040 1 1\nlast line has no newline / ext4 rw 4 5";

#[test]
fn parse_generated_file() {
    let path = tmp("tab1");
    std::fs::write(&path, TAB).unwrap();
    let p = path.to_str().unwrap();
    for bufsize in [4096, 1024, 200, 64, 30, 16, 8, 3, 2] {
        assert_eq!(read_ours(p, bufsize), read_host(p, bufsize), "buffer {bufsize}");
    }
}

#[test]
fn long_lines_and_stale_numbers() {
    let mut text = String::from("short / ext4 rw 1 1\nlong /");
    text.push_str(&"x".repeat(3000));
    text.push_str(" ext4 rw 2 2\nafter / ext4 rw 3 3\n");
    let path = tmp("tab2");
    std::fs::write(&path, &text).unwrap();
    for bufsize in [4096, 2048, 128] {
        assert_eq!(read_ours(path.to_str().unwrap(), bufsize), read_host(path.to_str().unwrap(), bufsize), "buffer {bufsize}");
    }
    // the last line ends in a blank without a newline: sscanf sees nothing and the numbers stay stale
    for (i, t) in ["a b c d 11 22\ne f g h ", "a b c d 11 22\ne f g h \t", "", "# c\n\n", "a", "a b c d e f g\n", "\n\n\n"].iter().enumerate() {
        let path = tmp(&format!("tab3-{i}"));
        std::fs::write(&path, t).unwrap();
        assert_eq!(read_ours(path.to_str().unwrap(), 4096), read_host(path.to_str().unwrap(), 4096), "text {t:?}");
    }
}

#[test]
fn system_files() {
    for p in ["/proc/self/mounts", "/proc/mounts", "/etc/fstab", "/nonexistent-dir/x"] {
        for bufsize in [4096, 256, 100] {
            assert_eq!(read_ours(p, bufsize), read_host(p, bufsize), "{p} buffer {bufsize}");
        }
    }
}

#[test]
fn getmntent_static_buffer() {
    unsafe {
        let path = tmp("tab5");
        std::fs::write(&path, "a /a t o 1 2\nb /b t o 3 4\n").unwrap();
        let p = CString::new(path.to_str().unwrap()).unwrap();
        let f = host::setmntent(p.as_ptr(), c"r".as_ptr());
        let g = mntent::setmntent(p.as_ptr(), c"r".as_ptr());
        for _ in 0..3 {
            let a = host::getmntent(f);
            let b = mntent::getmntent(g);
            assert_eq!(a.is_null(), b.is_null());
            if !a.is_null() {
                assert_eq!(row(&*a), row(&*b));
            }
        }
        assert_eq!(host::endmntent(f), mntent::endmntent(g));
        assert_eq!(mntent::endmntent(std::ptr::null_mut()), 1);
        assert!(mntent::setmntent(c"/nonexistent-dir/x".as_ptr(), c"r".as_ptr()).is_null());
    }
}

fn entries() -> Vec<[CString; 4]> {
    let c = |s: &[u8]| CString::new(s).unwrap();
    vec![
        [c(b"/dev/sda1"), c(b"/"), c(b"ext4"), c(b"rw,relatime")],
        [c(b"/dev/disk/by-label/My Disk"), c(b"/mnt/my disk"), c(b"vfat"), c(b"noauto,user")],
        [c(b"tab\there"), c(b"new\nline"), c(b"back\\slash"), c(b"")],
        [c(b""), c(b""), c(b""), c(b"")],
        [c(b"\x01\x80\xff"), c(b"#hash"), c(b"x\\040y"), c(b"a b")],
    ]
}

#[test]
fn addmntent_writes_the_same_bytes() {
    unsafe {
        let nums = [(0, 1), (0, 0), (-5, 123456), (0, 0), (i32::MAX, i32::MIN)];
        let (hp, op) = (tmp("add-host"), tmp("add-ours"));
        let (hc, oc) = (CString::new(hp.to_str().unwrap()).unwrap(), CString::new(op.to_str().unwrap()).unwrap());
        let hf = host::setmntent(hc.as_ptr(), c"w".as_ptr());
        let of = mntent::setmntent(oc.as_ptr(), c"w".as_ptr());
        for (e, (freq, pass)) in entries().iter().zip(nums) {
            let m = Mntent { mnt_fsname: e[0].as_ptr() as *mut c_char, mnt_dir: e[1].as_ptr() as *mut c_char, mnt_type: e[2].as_ptr() as *mut c_char, mnt_opts: e[3].as_ptr() as *mut c_char, mnt_freq: freq, mnt_passno: pass };
            assert_eq!(mntent::addmntent(of, &m), host::addmntent(hf, &m));
        }
        host::endmntent(hf);
        mntent::endmntent(of);
        assert_eq!(std::fs::read(&hp).unwrap(), std::fs::read(&op).unwrap());
        // appending, and adding after reading (the position moves to the end first)
        let hf = host::setmntent(hc.as_ptr(), c"r+".as_ptr());
        let of = mntent::setmntent(oc.as_ptr(), c"r+".as_ptr());
        let mut m1: Mntent = std::mem::zeroed();
        let mut m2: Mntent = std::mem::zeroed();
        let mut b1 = [0 as c_char; 1024];
        let mut b2 = [0 as c_char; 1024];
        let r1 = host::getmntent_r(hf, &mut m1, b1.as_mut_ptr(), 1024);
        let r2 = mntent::getmntent_r(of, &mut m2, b2.as_mut_ptr(), 1024);
        assert_eq!(row(&*r1), row(&*r2));
        let e = &entries()[0];
        let m = Mntent { mnt_fsname: e[0].as_ptr() as *mut c_char, mnt_dir: e[1].as_ptr() as *mut c_char, mnt_type: e[2].as_ptr() as *mut c_char, mnt_opts: e[3].as_ptr() as *mut c_char, mnt_freq: 9, mnt_passno: 9 };
        assert_eq!(mntent::addmntent(of, &m), host::addmntent(hf, &m));
        let r1 = host::getmntent_r(hf, &mut m1, b1.as_mut_ptr(), 1024);
        let r2 = mntent::getmntent_r(of, &mut m2, b2.as_mut_ptr(), 1024);
        assert_eq!(r1.is_null(), r2.is_null());
        host::endmntent(hf);
        mntent::endmntent(of);
        assert_eq!(std::fs::read(&hp).unwrap(), std::fs::read(&op).unwrap());
        // read-only stream: both fail
        let hf = host::setmntent(hc.as_ptr(), c"r".as_ptr());
        let of = mntent::setmntent(oc.as_ptr(), c"r".as_ptr());
        assert_eq!(mntent::addmntent(of, &m), host::addmntent(hf, &m));
        assert_eq!(host::endmntent(hf), mntent::endmntent(of));
        assert_eq!(read_ours(op.to_str().unwrap(), 4096), read_host(hp.to_str().unwrap(), 4096));
    }
}

#[test]
fn hasmntopt_matches() {
    let opts = ["rw,noatime,errors=remount-ro,nosuid,uid=1000,ro", "", "defaults", "x,rwx,rw,y", "a=b=c,d", "rw", "ro,", ",rw", ",,", "rw,,ro", "x=rw,rw", "rw=,rw"];
    let tests = ["rw", "ro", "noatime", "atime", "errors", "errors=remount-ro", "remount-ro", "nosuid", "suid", "uid", "uid=1000", "gid", "r", "o", "rw,noatime", "no", "", "a", "errors=", "ro,", "defaults", "default", "defaultsx", "a=b=c", "d", "b", "rwx", ",", ",rw", "=", "rw=", ",,"];
    for o in opts {
        let oc = CString::new(o).unwrap();
        let m = Mntent { mnt_fsname: c"fs".as_ptr() as *mut c_char, mnt_dir: c"/d".as_ptr() as *mut c_char, mnt_type: c"t".as_ptr() as *mut c_char, mnt_opts: oc.as_ptr() as *mut c_char, mnt_freq: 0, mnt_passno: 0 };
        for t in tests {
            let tc = CString::new(t).unwrap();
            let (a, b) = unsafe { (host::hasmntopt(&m, tc.as_ptr()), mntent::hasmntopt(&m, tc.as_ptr())) };
            let off = |p: *mut c_char| if p.is_null() { -1 } else { unsafe { p.offset_from(oc.as_ptr()) } };
            assert_eq!(off(a), off(b), "opts {o:?} opt {t:?}");
        }
    }
}

/// Every option string up to 6 bytes and every option up to 3 bytes over {r, w, ',', '='}: the same offset as the host.
#[test]
fn hasmntopt_exhaustive_small() {
    fn all(max: usize) -> Vec<Vec<u8>> {
        let mut v = vec![Vec::new()];
        let mut prev = vec![Vec::new()];
        for _ in 0..max {
            let next: Vec<Vec<u8>> = prev.iter().flat_map(|p: &Vec<u8>| b"rw,=".iter().map(move |&c| [&p[..], &[c]].concat())).collect();
            v.extend(next.iter().cloned());
            prev = next;
        }
        v
    }
    let tests: Vec<CString> = all(3).into_iter().map(|t| CString::new(t).unwrap()).collect();
    for o in all(6) {
        let oc = CString::new(o).unwrap();
        let m = Mntent { mnt_fsname: c"fs".as_ptr() as *mut c_char, mnt_dir: c"/d".as_ptr() as *mut c_char, mnt_type: c"t".as_ptr() as *mut c_char, mnt_opts: oc.as_ptr() as *mut c_char, mnt_freq: 0, mnt_passno: 0 };
        for tc in &tests {
            let (a, b) = unsafe { (host::hasmntopt(&m, tc.as_ptr()), mntent::hasmntopt(&m, tc.as_ptr())) };
            assert_eq!(a.is_null(), b.is_null(), "opts {oc:?} opt {tc:?}");
            if !a.is_null() {
                assert_eq!(a, b, "opts {oc:?} opt {tc:?}");
            }
        }
    }
}

#[test]
fn eof_state() {
    unsafe {
        let path = tmp("eof");
        std::fs::write(&path, "a b c d 1 2\n").unwrap();
        let p = CString::new(path.to_str().unwrap()).unwrap();
        let f = mntent::setmntent(p.as_ptr(), c"r".as_ptr());
        let mut m: Mntent = std::mem::zeroed();
        let mut buf = [0 as c_char; 256];
        assert!(!mntent::getmntent_r(f, &mut m, buf.as_mut_ptr(), 256).is_null());
        assert!(mntent::getmntent_r(f, &mut m, buf.as_mut_ptr(), 256).is_null());
        assert_ne!(rusty_libc_stdio::file_api::feof(f), 0);
        mntent::endmntent(f);
        let _ = host::feof;
    }
}
