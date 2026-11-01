#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
#![allow(clippy::type_complexity, clippy::useless_vec)]
//! Host tests for fstab.rs and ttyent.rs. The host libc reads /etc/fstab and /etc/ttys only, so: the real
//! /etc/fstab is compared with the host (every entry, lookups by device and by mount point); generated
//! files go through our reader and are compared with what the host's mntent parser says (the conversion rules
//! of fstab.c written out in the test); ttyent is checked against the format rules of the BSD source
//! (the C diff test in tests/c compares it with glibc inside a private /etc).
use crate::{fstab, ttyent};
use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

mod host {
    use super::*;
    #[repr(C)]
    pub struct Fstab {
        pub fs_spec: *mut c_char,
        pub fs_file: *mut c_char,
        pub fs_vfstype: *mut c_char,
        pub fs_mntops: *mut c_char,
        pub fs_type: *const c_char,
        pub fs_freq: c_int,
        pub fs_passno: c_int,
    }
    unsafe extern "C" {
        pub fn getfsent() -> *mut Fstab;
        pub fn getfsspec(n: *const c_char) -> *mut Fstab;
        pub fn getfsfile(n: *const c_char) -> *mut Fstab;
        pub fn setfsent() -> c_int;
        pub fn endfsent();
    }
}

type Rec = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, c_int, c_int);

fn s(p: *const c_char) -> Vec<u8> {
    if p.is_null() { b"<null>".to_vec() } else { unsafe { CStr::from_ptr(p) }.to_bytes().to_vec() }
}

fn ours(p: *mut fstab::Fstab) -> Option<Rec> {
    if p.is_null() {
        return None;
    }
    let f = unsafe { &*p };
    Some((s(f.fs_spec), s(f.fs_file), s(f.fs_vfstype), s(f.fs_mntops), s(f.fs_type), f.fs_freq, f.fs_passno))
}

fn theirs(p: *mut host::Fstab) -> Option<Rec> {
    if p.is_null() {
        return None;
    }
    let f = unsafe { &*p };
    Some((s(f.fs_spec), s(f.fs_file), s(f.fs_vfstype), s(f.fs_mntops), s(f.fs_type), f.fs_freq, f.fs_passno))
}

#[test]
fn real_fstab_matches_host() {
    let _g = LOCK.lock().unwrap();
    unsafe {
        crate::fstab::set_path(std::ptr::null());
        host::setfsent();
        assert_eq!(fstab::setfsent(), 1);
        let mut n = 0;
        loop {
            let a = ours(fstab::getfsent());
            let h = theirs(host::getfsent());
            assert_eq!(a, h);
            if a.is_none() {
                break;
            }
            n += 1;
        }
        assert!(n >= 1, "this machine's /etc/fstab has no entries");
        // lookups, each from the start of the file
        host::setfsent();
        fstab::setfsent();
        let mut names = vec![];
        loop {
            let p = host::getfsent();
            if p.is_null() {
                break;
            }
            names.push(((*p).fs_spec as usize, s((*p).fs_spec), s((*p).fs_file)));
        }
        for (_, spec, file) in &names {
            let (cs, cf) = (CString::new(spec.clone()).unwrap(), CString::new(file.clone()).unwrap());
            assert_eq!(ours(fstab::getfsspec(cs.as_ptr())), theirs(host::getfsspec(cs.as_ptr())));
            assert_eq!(ours(fstab::getfsfile(cf.as_ptr())), theirs(host::getfsfile(cf.as_ptr())));
        }
        for missing in [c"/no/such/device", c"", c"nosuchfile"] {
            assert_eq!(ours(fstab::getfsspec(missing.as_ptr())), None);
            assert_eq!(ours(fstab::getfsfile(missing.as_ptr())), None);
            assert!(host::getfsspec(missing.as_ptr()).is_null());
        }
        fstab::endfsent();
        host::endfsent();
        // after endfsent the next getfsent starts again
        assert_eq!(ours(fstab::getfsent()), theirs(host::getfsent()));
        fstab::endfsent();
        host::endfsent();
    }
}

#[test]
fn generated_fstab_conversion() {
    let _g = LOCK.lock().unwrap();
    let path = std::env::temp_dir().join(format!("rlibc-fstab-{}", std::process::id()));
    let text = "# comment\n\
        UUID=1111 / ext4 defaults,rw 1 1\n\
        /dev/sda2 /boot ext4 ro,nosuid 1 2\n\
        /dev/sda3 none swap sw 0 0\n\
        /dev/sda4 /q xfs usrquota,rq 0 0\n\
        /dev/sda5 /x ext4 xx 0 0\n\
        /dev/sda6 /u ext4 noauto 0 0\n\
        /dev/sda7 /both ext4 ro,rw 0 0\n\
        \n\
        spaced\\040dev /mnt/a\\040b ext4 defaults\n\
        short /s\n\
        tmpfs /tmp tmpfs rwx,nosuid 0 0\n";
    std::fs::write(&path, text).unwrap();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    unsafe {
        fstab::set_path(cpath.as_ptr());
        assert_eq!(fstab::setfsent(), 1);
        let mut got = vec![];
        loop {
            let p = fstab::getfsent();
            if p.is_null() {
                break;
            }
            got.push(ours(p).unwrap());
        }
        let want: Vec<Rec> = vec![
            (b"UUID=1111".to_vec(), b"/".to_vec(), b"ext4".to_vec(), b"defaults,rw".to_vec(), b"rw".to_vec(), 1, 1),
            (b"/dev/sda2".to_vec(), b"/boot".to_vec(), b"ext4".to_vec(), b"ro,nosuid".to_vec(), b"ro".to_vec(), 1, 2),
            (b"/dev/sda3".to_vec(), b"none".to_vec(), b"swap".to_vec(), b"sw".to_vec(), b"sw".to_vec(), 0, 0),
            (b"/dev/sda4".to_vec(), b"/q".to_vec(), b"xfs".to_vec(), b"usrquota,rq".to_vec(), b"rq".to_vec(), 0, 0),
            (b"/dev/sda5".to_vec(), b"/x".to_vec(), b"ext4".to_vec(), b"xx".to_vec(), b"xx".to_vec(), 0, 0),
            (b"/dev/sda6".to_vec(), b"/u".to_vec(), b"ext4".to_vec(), b"noauto".to_vec(), b"??".to_vec(), 0, 0),
            (b"/dev/sda7".to_vec(), b"/both".to_vec(), b"ext4".to_vec(), b"ro,rw".to_vec(), b"rw".to_vec(), 0, 0),
            (b"spaced dev".to_vec(), b"/mnt/a b".to_vec(), b"ext4".to_vec(), b"defaults".to_vec(), b"??".to_vec(), 0, 0),
            (b"short".to_vec(), b"/s".to_vec(), b"".to_vec(), b"".to_vec(), b"??".to_vec(), 0, 0),
            (b"tmpfs".to_vec(), b"/tmp".to_vec(), b"tmpfs".to_vec(), b"rwx,nosuid".to_vec(), b"??".to_vec(), 0, 0),
        ];
        assert_eq!(got, want);
        // by device and by mount point
        assert_eq!(ours(fstab::getfsspec(c"/dev/sda2".as_ptr())).unwrap().1, b"/boot");
        assert_eq!(ours(fstab::getfsfile(c"/mnt/a b".as_ptr())).unwrap().0, b"spaced dev");
        assert!(fstab::getfsfile(c"/nope".as_ptr()).is_null());
        fstab::endfsent();
        // a missing file: nothing, setfsent says 0
        fstab::set_path(c"/nonexistent/fstab".as_ptr());
        assert_eq!(fstab::setfsent(), 0);
        assert!(fstab::getfsent().is_null());
        fstab::set_path(std::ptr::null());
    }
    let _ = std::fs::remove_file(&path);
}

fn tty(p: *mut ttyent::Ttyent) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, c_int, Vec<u8>, Vec<u8>)> {
    if p.is_null() {
        return None;
    }
    let t = unsafe { &*p };
    Some((s(t.ty_name), s(t.ty_getty), s(t.ty_type), t.ty_status, s(t.ty_window), s(t.ty_comment)))
}

#[test]
fn ttyent_format() {
    let _g = LOCK.lock().unwrap();
    let path = std::env::temp_dir().join(format!("rlibc-ttys-{}", std::process::id()));
    let long = format!("tty-long \"/usr/libexec/{}\" vt100 on\n", "x".repeat(150));
    let text = format!(
        "# a comment\n\
         \n\
         console \"/usr/libexec/getty std.9600\" vt100 on secure\n\
         ttyv0 \"/usr/libexec/getty Pc\" cons25 on secure window=\"/usr/bin/xdm -n\" # a comment here\n\
         ttyv1\t\"/usr/libexec/getty Pc\"\tcons25\toff\n\
         ttyv2 none\n\
         ttyv3\n\
         {long}\
         ttyd0 \"/usr/libexec/getty std.9600\" dialup on # quoted \\\" comment\n\
         ttyd1 \"a \\\"quoted\\\" cmd\" unknown on off secure\n\
         ttyd2 getty unknown # only comment\n\
         last getty vt on"
    );
    std::fs::write(&path, &text).unwrap();
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    unsafe {
        ttyent::set_path(cpath.as_ptr());
        assert_eq!(ttyent::setttyent(), 1);
        let mut got = vec![];
        loop {
            let p = ttyent::getttyent();
            if p.is_null() {
                break;
            }
            got.push(tty(p).unwrap());
        }
        let v = |x: &str| x.as_bytes().to_vec();
        let n = b"<null>".to_vec();
        let want = vec![
            (v("console"), v("/usr/libexec/getty std.9600"), v("vt100"), 3, n.clone(), n.clone()),
            (v("ttyv0"), v("/usr/libexec/getty Pc"), v("cons25"), 3, v("/usr/bin/xdm -n"), v("a comment here")),
            (v("ttyv1"), v("/usr/libexec/getty Pc"), v("cons25"), 0, n.clone(), n.clone()),
            (v("ttyv2"), v("none"), n.clone(), 0, n.clone(), n.clone()),
            (v("ttyv3"), n.clone(), n.clone(), 0, n.clone(), n.clone()),
            (v("ttyd0"), v("/usr/libexec/getty std.9600"), v("dialup"), 1, n.clone(), v("quoted \\\" comment")),
        ];
        // lines up to the "tty-long" one are exact; the too long line is skipped; the rest are checked loosely
        assert_eq!(&got[..6], &want[..]);
        assert!(!got.iter().any(|t| t.0 == b"tty-long"), "a line over 99 characters is skipped");
        let names: Vec<_> = got.iter().map(|t| String::from_utf8_lossy(&t.0).into_owned()).collect();
        assert_eq!(names, ["console", "ttyv0", "ttyv1", "ttyv2", "ttyv3", "ttyd0", "ttyd1", "ttyd2"]); // the last line has no newline: dropped like a line that is too long
        let d1 = &got[6];
        assert_eq!(d1.1, b"a \"quoted\" cmd");
        assert_eq!(d1.2, b"unknown");
        assert_eq!(d1.3, 2); // on, then off, then secure
        // by name (the file is opened and closed again) and rewinding
        assert_eq!(tty(ttyent::getttynam(c"ttyv1".as_ptr())).unwrap().2, b"cons25");
        assert!(ttyent::getttynam(c"nothing".as_ptr()).is_null());
        assert_eq!(ttyent::endttyent(), 1);
        assert_eq!(ttyent::endttyent(), 1);
        assert_eq!(ttyent::setttyent(), 1);
        assert_eq!(tty(ttyent::getttyent()).unwrap().0, b"console");
        assert_eq!(ttyent::setttyent(), 1);
        assert_eq!(tty(ttyent::getttyent()).unwrap().0, b"console");
        ttyent::endttyent();
        ttyent::set_path(c"/nonexistent/ttys".as_ptr());
        assert_eq!(ttyent::setttyent(), 0);
        assert!(ttyent::getttyent().is_null());
        ttyent::set_path(std::ptr::null());
    }
    let _ = std::fs::remove_file(&path);
}
