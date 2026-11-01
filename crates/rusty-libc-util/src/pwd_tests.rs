//! Differential tests for pwd.rs against the host glibc.
//!
//! Notes on what is compared: the host resolves through NSS (here `files systemd`; groups merge
//! with systemd-userdb), ours reads the files only. So lookups compare only names and ids that
//! `/etc/passwd` and `/etc/group` contain, enumerations compare the first N entries of the host
//! (N = what the file holds), and shadow is compared through temporary files (`/etc/shadow` is
//! unreadable for a normal user; for it only the failure mode is compared).
use crate::pwd::*;
use crate::testutil::Rng;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use std::ffi::{CStr, CString};

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn getpwnam_r(n: *const c_char, r: *mut Passwd, b: *mut c_char, l: usize, o: *mut *mut Passwd) -> c_int;
        pub fn getpwuid_r(u: u32, r: *mut Passwd, b: *mut c_char, l: usize, o: *mut *mut Passwd) -> c_int;
        pub fn getpwnam(n: *const c_char) -> *mut Passwd;
        pub fn getpwuid(u: u32) -> *mut Passwd;
        pub fn getpwent() -> *mut Passwd;
        pub fn setpwent();
        pub fn endpwent();
        pub fn fgetpwent_r(f: *mut c_void, r: *mut Passwd, b: *mut c_char, l: usize, o: *mut *mut Passwd) -> c_int;
        pub fn fgetpwent(f: *mut c_void) -> *mut Passwd;
        pub fn putpwent(p: *const Passwd, f: *mut c_void) -> c_int;
        pub fn getpw(u: u32, buf: *mut c_char) -> c_int;
        pub fn getgrnam_r(n: *const c_char, r: *mut Group, b: *mut c_char, l: usize, o: *mut *mut Group) -> c_int;
        pub fn getgrgid_r(g: u32, r: *mut Group, b: *mut c_char, l: usize, o: *mut *mut Group) -> c_int;
        pub fn getgrnam(n: *const c_char) -> *mut Group;
        pub fn getgrgid(g: u32) -> *mut Group;
        pub fn getgrent() -> *mut Group;
        pub fn setgrent();
        pub fn endgrent();
        pub fn fgetgrent_r(f: *mut c_void, r: *mut Group, b: *mut c_char, l: usize, o: *mut *mut Group) -> c_int;
        pub fn fgetgrent(f: *mut c_void) -> *mut Group;
        pub fn putgrent(p: *const Group, f: *mut c_void) -> c_int;
        pub fn getgrouplist(u: *const c_char, g: u32, gs: *mut u32, n: *mut c_int) -> c_int;
        pub fn fgetspent_r(f: *mut c_void, r: *mut Spwd, b: *mut c_char, l: usize, o: *mut *mut Spwd) -> c_int;
        pub fn sgetspent_r(s: *const c_char, r: *mut Spwd, b: *mut c_char, l: usize, o: *mut *mut Spwd) -> c_int;
        pub fn sgetspent(s: *const c_char) -> *mut Spwd;
        pub fn putspent(p: *const Spwd, f: *mut c_void) -> c_int;
        pub fn fgetsgent_r(f: *mut c_void, r: *mut Sgrp, b: *mut c_char, l: usize, o: *mut *mut Sgrp) -> c_int;
        pub fn fgetsgent(f: *mut c_void) -> *mut Sgrp;
        pub fn sgetsgent_r(s: *const c_char, r: *mut Sgrp, b: *mut c_char, l: usize, o: *mut *mut Sgrp) -> c_int;
        pub fn sgetsgent(s: *const c_char) -> *mut Sgrp;
        pub fn putsgent(p: *const Sgrp, f: *mut c_void) -> c_int;
        pub fn lckpwdf() -> c_int;
        pub fn ulckpwdf() -> c_int;
        pub fn getlogin() -> *mut c_char;
        pub fn getlogin_r(b: *mut c_char, l: usize) -> c_int;
        pub fn getusershell() -> *mut c_char;
        pub fn setusershell();
        pub fn endusershell();
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}

unsafe fn herrno() -> i32 {
    unsafe { *host::__errno_location() }
}
unsafe fn hset_errno(v: i32) {
    unsafe { *host::__errno_location() = v }
}

type Bytes = Option<Vec<u8>>;

fn b(p: *const c_char) -> Bytes {
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()) }
}

#[derive(Debug, PartialEq)]
struct PwRec {
    name: Bytes,
    passwd: Bytes,
    uid: u32,
    gid: u32,
    gecos: Bytes,
    dir: Bytes,
    shell: Bytes,
}

fn pw(p: *const Passwd) -> Option<PwRec> {
    if p.is_null() {
        return None;
    }
    let p = unsafe { &*p };
    Some(PwRec { name: b(p.pw_name), passwd: b(p.pw_passwd), uid: p.pw_uid, gid: p.pw_gid, gecos: b(p.pw_gecos), dir: b(p.pw_dir), shell: b(p.pw_shell) })
}

#[derive(Debug, PartialEq)]
struct GrRec {
    name: Bytes,
    passwd: Bytes,
    gid: u32,
    mem: Option<Vec<Vec<u8>>>,
}

fn gr(p: *const Group) -> Option<GrRec> {
    if p.is_null() {
        return None;
    }
    let g = unsafe { &*p };
    let mem = if g.gr_mem.is_null() {
        None
    } else {
        let mut v = vec![];
        let mut i = 0;
        unsafe {
            while !(*g.gr_mem.add(i)).is_null() {
                v.push(CStr::from_ptr(*g.gr_mem.add(i)).to_bytes().to_vec());
                i += 1;
            }
        }
        Some(v)
    };
    Some(GrRec { name: b(g.gr_name), passwd: b(g.gr_passwd), gid: g.gr_gid, mem })
}

#[derive(Debug, PartialEq)]
struct SpRec {
    namp: Bytes,
    pwdp: Bytes,
    nums: [i64; 6],
    flag: u64,
}

fn sp(p: *const Spwd) -> Option<SpRec> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { &*p };
    Some(SpRec { namp: b(s.sp_namp), pwdp: b(s.sp_pwdp), nums: [s.sp_lstchg, s.sp_min, s.sp_max, s.sp_warn, s.sp_inact, s.sp_expire], flag: s.sp_flag })
}

fn read_names(path: &str) -> Vec<(Vec<u8>, u32)> {
    // (name, id) of every well-formed line: name:x:id:...
    std::fs::read(path)
        .unwrap()
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty() && l[0] != b'#' && l[0] != b'+' && l[0] != b'-')
        .filter_map(|l| {
            let f: Vec<&[u8]> = l.split(|&c| c == b':').collect();
            if f.len() < 3 {
                return None;
            }
            let id = std::str::from_utf8(f[2]).ok()?.parse::<u32>().ok()?;
            Some((f[0].to_vec(), id))
        })
        .collect()
}

fn cs(v: &[u8]) -> CString {
    CString::new(v).unwrap()
}

#[test]
fn passwd_lookups_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let names = read_names("/etc/passwd");
    assert!(names.len() > 5);
    for (name, uid) in &names {
        let cn = cs(name);
        let mut bo = vec![0u8; 4096];
        let mut bh = vec![0u8; 4096];
        let (mut ro, mut rh): (*mut Passwd, *mut Passwd) = (null_mut(), null_mut());
        let mut so: Passwd = unsafe { core::mem::zeroed() };
        let mut sh: Passwd = unsafe { core::mem::zeroed() };
        unsafe {
            rusty_libc_core::errno::set(77);
            hset_errno(77);
            let a = getpwnam_r(cn.as_ptr(), &mut so, bo.as_mut_ptr().cast(), bo.len(), &mut ro);
            let h = host::getpwnam_r(cn.as_ptr(), &mut sh, bh.as_mut_ptr().cast(), bh.len(), &mut rh);
            assert_eq!((a, rusty_libc_core::errno::get()), (h, herrno()), "getpwnam_r {:?}", String::from_utf8_lossy(name));
            assert_eq!(pw(ro), pw(rh), "getpwnam_r {:?}", String::from_utf8_lossy(name));
            // non-reentrant
            assert_eq!(pw(getpwnam(cn.as_ptr())), pw(host::getpwnam(cn.as_ptr())));
            // by uid: the first entry with that uid wins in both
            let a = getpwuid_r(*uid, &mut so, bo.as_mut_ptr().cast(), bo.len(), &mut ro);
            let h = host::getpwuid_r(*uid, &mut sh, bh.as_mut_ptr().cast(), bh.len(), &mut rh);
            assert_eq!(a, h);
            assert_eq!(pw(ro), pw(rh), "getpwuid_r {uid}");
            assert_eq!(pw(getpwuid(*uid)), pw(host::getpwuid(*uid)));
        }
    }
    // names that do not exist
    for name in ["no-such-user-xyz", "", "+", "-x", "root:x", "a b"] {
        let cn = CString::new(name).unwrap();
        let mut buf = vec![0u8; 4096];
        let (mut ro, mut rh): (*mut Passwd, *mut Passwd) = (null_mut(), null_mut());
        let mut so: Passwd = unsafe { core::mem::zeroed() };
        let mut sh: Passwd = unsafe { core::mem::zeroed() };
        unsafe {
            rusty_libc_core::errno::set(77);
            hset_errno(77);
            let a = getpwnam_r(cn.as_ptr(), &mut so, buf.as_mut_ptr().cast(), buf.len(), &mut ro);
            let h = host::getpwnam_r(cn.as_ptr(), &mut sh, buf.as_mut_ptr().cast(), buf.len(), &mut rh);
            assert_eq!((a, ro.is_null(), rusty_libc_core::errno::get()), (h, rh.is_null(), herrno()), "missing name {name:?}");
        }
    }
    unsafe {
        let mut so: Passwd = core::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut ro: *mut Passwd = null_mut();
        assert_eq!(getpwuid_r(54321, &mut so, buf.as_mut_ptr().cast(), buf.len(), &mut ro), 0);
        assert!(ro.is_null());
    }
}

#[test]
fn passwd_buffer_sizes_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let names = read_names("/etc/passwd");
    let longest = std::fs::read("/etc/passwd").unwrap().split(|&c| c == b'\n').map(|l| l.len()).max().unwrap();
    for (name, uid) in &names {
        let cn = cs(name);
        for len in 0..=longest + 6 {
            let mut buf = vec![0u8; len.max(1)];
            let mut buf2 = vec![0u8; len.max(1)];
            let (mut ro, mut rh): (*mut Passwd, *mut Passwd) = (null_mut(), null_mut());
            let mut so: Passwd = unsafe { core::mem::zeroed() };
            let mut sh: Passwd = unsafe { core::mem::zeroed() };
            unsafe {
                let a = getpwnam_r(cn.as_ptr(), &mut so, buf.as_mut_ptr().cast(), len, &mut ro);
                let h = host::getpwnam_r(cn.as_ptr(), &mut sh, buf2.as_mut_ptr().cast(), len, &mut rh);
                assert_eq!((a, ro.is_null()), (h, rh.is_null()), "getpwnam_r {:?} buflen {len}", String::from_utf8_lossy(name));
                if a == 0 && !ro.is_null() {
                    assert_eq!(pw(ro), pw(rh));
                }
                let a = getpwuid_r(*uid, &mut so, buf.as_mut_ptr().cast(), len, &mut ro);
                let h = host::getpwuid_r(*uid, &mut sh, buf2.as_mut_ptr().cast(), len, &mut rh);
                assert_eq!((a, ro.is_null()), (h, rh.is_null()), "getpwuid_r {uid} buflen {len}");
            }
        }
    }
}

#[test]
fn passwd_enumeration_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let text = std::fs::read("/etc/passwd").unwrap();
    // number of lines the parser will accept: ours is checked against the host's first N
    let mut ours = vec![];
    unsafe {
        setpwent();
        loop {
            let p = getpwent();
            if p.is_null() {
                break;
            }
            ours.push(pw(p).unwrap());
        }
        // another getpwent_r after the end keeps saying ENOENT
        let mut r: Passwd = core::mem::zeroed();
        let mut buf = [0u8; 2048];
        let mut o: *mut Passwd = null_mut();
        assert_eq!(getpwent_r(&mut r, buf.as_mut_ptr().cast(), buf.len(), &mut o), ENOENT_);
        assert!(o.is_null());
        endpwent();
    }
    assert!(ours.len() >= read_names("/etc/passwd").len());
    let mut hostv = vec![];
    unsafe {
        host::setpwent();
        for _ in 0..ours.len() {
            let p = host::getpwent();
            if p.is_null() {
                break;
            }
            hostv.push(pw(p).unwrap());
        }
        host::endpwent();
    }
    assert_eq!(ours, hostv, "enumeration (passwd file: {} bytes)", text.len());
    // setpwent restarts; getpwent_r with a small buffer reports ERANGE and then reads the same entry
    unsafe {
        setpwent();
        let mut r: Passwd = core::mem::zeroed();
        let mut tiny = [0u8; 4];
        let mut o: *mut Passwd = null_mut();
        assert_eq!(getpwent_r(&mut r, tiny.as_mut_ptr().cast(), tiny.len(), &mut o), ERANGE_);
        let mut buf = [0u8; 2048];
        assert_eq!(getpwent_r(&mut r, buf.as_mut_ptr().cast(), buf.len(), &mut o), 0);
        assert_eq!(pw(o).unwrap(), ours[0]);
        endpwent();
    }
}

const ENOENT_: i32 = 2;
const ERANGE_: i32 = 34;

#[test]
fn getpw_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for (_, uid) in read_names("/etc/passwd") {
        let mut a = [0u8; 1024];
        let mut h = [0u8; 1024];
        unsafe {
            let ra = getpw(uid, a.as_mut_ptr().cast());
            let rh = host::getpw(uid, h.as_mut_ptr().cast());
            assert_eq!(ra, rh);
            assert_eq!(a, h);
        }
    }
    unsafe {
        assert_eq!(getpw(1, null_mut()), -1);
    }
}

// ---------------------------------------------------------------- generated files

fn tmpfile_path(tag: &str) -> String {
    format!("/tmp/rusty-libc-util-pwd-{}-{}", std::process::id(), tag)
}

fn gen_pw_line(r: &mut Rng) -> Vec<u8> {
    let nums = ["0", "1000", "-1", "-5", "4294967295", "4294967296", "99999999999999999999", "12abc", "", "  7", "+3", "0x10", "65534", "5 "];
    let strs = ["x", "", "*", "!", "pw hash", "Full Name,,,", "/home/u", "/bin/bash", "a:b", "tab\there"];
    let names = ["root", "a", "user1", "+", "-", "+@nis", "-user", "", "x y", "#hash", "name"];
    let mut l = String::new();
    match r.below(10) {
        0 => return b"# a comment".to_vec(),
        1 => return b"".to_vec(),
        2 => return b"   ".to_vec(),
        _ => {}
    }
    if r.chance(15) {
        l.push_str(["  ", "\t", " "][r.below(3)]);
    }
    l.push_str(names[r.below(names.len())]);
    let nf = r.below(8);
    for i in 0..nf {
        l.push(':');
        if i == 1 || i == 2 {
            l.push_str(nums[r.below(nums.len())]);
        } else if r.chance(3) {
            l.push_str(&"g".repeat(300 + r.below(200)));
        } else {
            l.push_str(strs[r.below(strs.len())]);
        }
    }
    if r.chance(5) {
        l.push('\r');
    }
    l.into_bytes()
}

fn gen_gr_line(r: &mut Rng) -> Vec<u8> {
    let nums = ["0", "100", "-1", "4294967295", "4294967296", "12abc", "", " 5", "+3"];
    let mems = ["", "a", "a,b", "a, b ,c", ",a,,b,", " ", "adam,wheel,root", "x,y,z,w,v,u,t,s,r,q,p,o,n,m,l,k", "a b"];
    let names = ["wheel", "g", "+", "-", "+@x", "", "name", "#c"];
    match r.below(10) {
        0 => return b"# a comment".to_vec(),
        1 => return b"".to_vec(),
        _ => {}
    }
    let mut l = String::new();
    if r.chance(10) {
        l.push(' ');
    }
    l.push_str(names[r.below(names.len())]);
    let nf = r.below(5);
    for i in 0..nf {
        l.push(':');
        if i == 1 {
            l.push_str(nums[r.below(nums.len())]);
        } else if i == 2 {
            if r.chance(5) {
                for k in 0..(20 + r.below(40)) {
                    if k > 0 {
                        l.push(',');
                    }
                    l.push_str(&format!("member{k}"));
                }
            } else {
                l.push_str(mems[r.below(mems.len())]);
            }
        } else {
            l.push_str(["x", "", "*"][r.below(3)]);
        }
    }
    if r.chance(5) {
        l.push('\r');
    }
    l.into_bytes()
}

fn gen_sp_line(r: &mut Rng) -> Vec<u8> {
    let nums = ["0", "19000", "-1", "", "99999", "4294967295", "4294967296", "12abc", " 5", "7 ", "1x"];
    let names = ["root", "a", "+", "-", "+@x", "", "name", "#c"];
    match r.below(10) {
        0 => return b"# a comment".to_vec(),
        1 => return b"".to_vec(),
        _ => {}
    }
    let mut l = String::new();
    if r.chance(10) {
        l.push(' ');
    }
    l.push_str(names[r.below(names.len())]);
    let nf = r.below(11);
    for i in 0..nf {
        l.push(':');
        if i == 0 {
            l.push_str(["$6$salt$hash", "*", "!", "", "!!"][r.below(5)]);
        } else {
            l.push_str(nums[r.below(nums.len())]);
        }
    }
    if r.chance(5) {
        l.push('\r');
    }
    l.into_bytes()
}

fn gen_file(r: &mut Rng, generator: fn(&mut Rng) -> Vec<u8>) -> Vec<u8> {
    let n = 1 + r.below(8);
    let mut out = vec![];
    for i in 0..n {
        out.extend(generator(r));
        if i + 1 < n || r.chance(70) {
            out.push(b'\n');
        }
    }
    out
}

/// Run one stream reader over a file with a given buffer length and log what it sees.
fn log_reader<R: PartialEq + core::fmt::Debug>(mut next: impl FnMut(usize) -> (c_int, Option<R>), buflen: usize) -> Vec<(c_int, Option<R>)> {
    let mut out = vec![];
    for _ in 0..40 {
        let (rc, rec) = next(buflen);
        let stop = rc != 0;
        out.push((rc, rec));
        if stop {
            break;
        }
    }
    out
}

macro_rules! stream_test {
    ($name:ident, $gen:ident, $ty:ty, $ours:ident, $host:ident, $rec:ident, $tag:expr, $min:expr) => {
        #[test]
        fn $name() {
            let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut r = Rng(0xfeed_f00d_1234_5678);
            let path = tmpfile_path($tag);
            let cpath = CString::new(path.clone()).unwrap();
            let mut ok_entries = 0usize;
            for case in 0..1500 {
                let data = gen_file(&mut r, $gen);
                std::fs::write(&path, &data).unwrap();
                for buflen in [0usize, 1, 3, 8, 20, 64, 100, 300, 1024] {
                    let fo = unsafe { rusty_libc_stdio::fopen(cpath.as_ptr(), c"r".as_ptr()) };
                    let fh = unsafe { host::fopen(cpath.as_ptr(), c"r".as_ptr()) };
                    let mut bo = vec![0u8; buflen.max(1)];
                    let mut bh = vec![0u8; buflen.max(1)];
                    let lo = log_reader(
                        |n| unsafe {
                            let mut res: $ty = core::mem::zeroed();
                            let mut out: *mut $ty = null_mut();
                            let rc = $ours(fo, &mut res, bo.as_mut_ptr().cast(), n, &mut out);
                            (rc, $rec(out))
                        },
                        buflen,
                    );
                    let lh = log_reader(
                        |n| unsafe {
                            let mut res: $ty = core::mem::zeroed();
                            let mut out: *mut $ty = null_mut();
                            let rc = host::$host(fh, &mut res, bh.as_mut_ptr().cast(), n, &mut out);
                            (rc, $rec(out))
                        },
                        buflen,
                    );
                    unsafe {
                        rusty_libc_stdio::fclose(fo);
                        host::fclose(fh);
                    }
                    ok_entries += lo.iter().filter(|(rc, _)| *rc == 0).count();
                    assert_eq!(lo, lh, "case {case} buflen {buflen} file {:?}", String::from_utf8_lossy(&data));
                }
            }
            let _ = std::fs::remove_file(&path);
            assert!(ok_entries > $min, "only {ok_entries} entries parsed: generator too weak");
        }
    };
}

stream_test!(fgetpwent_r_matches_host, gen_pw_line, Passwd, fgetpwent_r, fgetpwent_r, pw, "fgetpw", 3000);
stream_test!(fgetgrent_r_matches_host, gen_gr_line, Group, fgetgrent_r, fgetgrent_r, gr, "fgetgr", 3000);
stream_test!(fgetspent_r_matches_host, gen_sp_line, Spwd, fgetspent_r, fgetspent_r, sp, "fgetsp", 1000);

#[test]
fn fgetent_nonreentrant_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xabcdef);
    let path = tmpfile_path("fget-nr");
    let cpath = CString::new(path.clone()).unwrap();
    for _ in 0..300 {
        let mut data = gen_file(&mut r, gen_pw_line);
        // include a line longer than the initial 1024-byte buffer
        if r.chance(50) {
            data.extend(b"\nlong:x:1:2:");
            data.extend(std::iter::repeat_n(b'q', 1500));
            data.extend(b":/h:/s\nlast:x:3:4:g:/h:/s\n");
        }
        std::fs::write(&path, &data).unwrap();
        unsafe {
            let fo = rusty_libc_stdio::fopen(cpath.as_ptr(), c"r".as_ptr());
            let fh = host::fopen(cpath.as_ptr(), c"r".as_ptr());
            for _ in 0..12 {
                let a = pw(fgetpwent(fo));
                let h = pw(host::fgetpwent(fh));
                assert_eq!(a, h);
                if a.is_none() {
                    break;
                }
            }
            rusty_libc_stdio::fclose(fo);
            host::fclose(fh);
        }
        let mut data = gen_file(&mut r, gen_gr_line);
        data.extend(b"\nbig:x:5:");
        for k in 0..400 {
            data.extend(format!("u{k},").bytes());
        }
        data.extend(b"\nnext:x:6:a\n");
        std::fs::write(&path, &data).unwrap();
        unsafe {
            let fo = rusty_libc_stdio::fopen(cpath.as_ptr(), c"r".as_ptr());
            let fh = host::fopen(cpath.as_ptr(), c"r".as_ptr());
            for _ in 0..12 {
                let a = gr(fgetgrent(fo));
                let h = gr(host::fgetgrent(fh));
                assert_eq!(a, h);
                if a.is_none() {
                    break;
                }
            }
            rusty_libc_stdio::fclose(fo);
            host::fclose(fh);
        }
    }
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------- put*ent

fn write_ours(f: impl FnOnce(*mut rusty_libc_stdio::file::File) -> c_int, path: &str) -> (c_int, Vec<u8>, i32) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        let fp = rusty_libc_stdio::fopen(cpath.as_ptr(), c"w".as_ptr());
        rusty_libc_core::errno::set(0);
        let rc = f(fp);
        let e = rusty_libc_core::errno::get();
        rusty_libc_stdio::fclose(fp);
        (rc, std::fs::read(path).unwrap(), e)
    }
}

fn write_host(f: impl FnOnce(*mut c_void) -> c_int, path: &str) -> (c_int, Vec<u8>, i32) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        let fp = host::fopen(cpath.as_ptr(), c"w".as_ptr());
        hset_errno(0);
        let rc = f(fp);
        let e = herrno();
        host::fclose(fp);
        (rc, std::fs::read(path).unwrap(), e)
    }
}

#[test]
fn putpwent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmpfile_path("putpw");
    let strs: [Option<&CStr>; 8] = [Some(c"root"), Some(c"+"), Some(c"-@x"), None, Some(c""), Some(c"a:b"), Some(c"line\nbreak"), Some(c"Name, Inc.")];
    let mut r = Rng(11);
    for _ in 0..3000 {
        let pick = |r: &mut Rng| strs[r.below(strs.len())].map_or(null_mut(), |s| s.as_ptr() as *mut c_char);
        let p = Passwd { pw_name: pick(&mut r), pw_passwd: pick(&mut r), pw_uid: [0, 1, 1000, u32::MAX][r.below(4)], pw_gid: [0, 7, u32::MAX][r.below(3)], pw_gecos: pick(&mut r), pw_dir: pick(&mut r), pw_shell: pick(&mut r) };
        let a = write_ours(|f| unsafe { putpwent(&p, f) }, &path);
        let h = write_host(|f| unsafe { host::putpwent(&p, f) }, &path);
        assert_eq!((a.0, &a.1), (h.0, &h.1), "putpwent {:?}", pw(&p));
        if a.0 != 0 {
            assert_eq!(a.2, h.2);
        }
    }
    // NULL arguments
    unsafe {
        rusty_libc_core::errno::set(0);
        assert_eq!(putpwent(core::ptr::null(), null_mut()), -1);
        assert_eq!(rusty_libc_core::errno::get(), 22);
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn putgrent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmpfile_path("putgr");
    let strs: [Option<&CStr>; 6] = [Some(c"wheel"), Some(c"+"), None, Some(c""), Some(c"a:b"), Some(c"x")];
    let mem_sets: [Option<Vec<&CStr>>; 5] = [None, Some(vec![]), Some(vec![c"a"]), Some(vec![c"a", c"b", c"c"]), Some(vec![c"a", c"b,c"])];
    let mut r = Rng(12);
    for _ in 0..3000 {
        let pick = |r: &mut Rng| strs[r.below(strs.len())].map_or(null_mut(), |s| s.as_ptr() as *mut c_char);
        let ms = &mem_sets[r.below(mem_sets.len())];
        let mut ptrs: Vec<*mut c_char> = ms.as_ref().map_or(vec![], |v| v.iter().map(|s| s.as_ptr() as *mut c_char).collect());
        ptrs.push(null_mut());
        let g = Group { gr_name: pick(&mut r), gr_passwd: pick(&mut r), gr_gid: [0, 9, u32::MAX][r.below(3)], gr_mem: if ms.is_some() { ptrs.as_mut_ptr() } else { null_mut() } };
        let a = write_ours(|f| unsafe { putgrent(&g, f) }, &path);
        let h = write_host(|f| unsafe { host::putgrent(&g, f) }, &path);
        assert_eq!((a.0, &a.1), (h.0, &h.1), "putgrent {:?}", gr(&g));
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn putspent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmpfile_path("putsp");
    let strs: [Option<&CStr>; 6] = [Some(c"root"), Some(c"+"), None, Some(c""), Some(c"a:b"), Some(c"$6$x$y")];
    let vals = [-1i64, 0, 1, 19000, 99999, -7, i64::MAX];
    let mut r = Rng(13);
    for _ in 0..3000 {
        let pick = |r: &mut Rng| strs[r.below(strs.len())].map_or(null_mut(), |s| s.as_ptr() as *mut c_char);
        let v = |r: &mut Rng| vals[r.below(vals.len())];
        let s = Spwd { sp_namp: pick(&mut r), sp_pwdp: pick(&mut r), sp_lstchg: v(&mut r), sp_min: v(&mut r), sp_max: v(&mut r), sp_warn: v(&mut r), sp_inact: v(&mut r), sp_expire: v(&mut r), sp_flag: [!0u64, 0, 5, 1 << 63][r.below(4)] };
        let a = write_ours(|f| unsafe { putspent(&s, f) }, &path);
        let h = write_host(|f| unsafe { host::putspent(&s, f) }, &path);
        assert_eq!((a.0, &a.1), (h.0, &h.1), "putspent {:?}", sp(&s));
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn sgetspent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(14);
    let mut parsed = 0;
    for _ in 0..20000 {
        let line = gen_sp_line(&mut r);
        let cl = CString::new(line.clone()).unwrap();
        for buflen in [8usize, 30, 80, 200, 1024] {
            let mut bo = vec![0u8; buflen];
            let mut bh = vec![0u8; buflen];
            let mut ro: Spwd = unsafe { core::mem::zeroed() };
            let mut rh: Spwd = unsafe { core::mem::zeroed() };
            let (mut oo, mut oh): (*mut Spwd, *mut Spwd) = (null_mut(), null_mut());
            unsafe {
                rusty_libc_core::errno::set(0);
                hset_errno(0);
                let a = sgetspent_r(cl.as_ptr(), &mut ro, bo.as_mut_ptr().cast(), buflen, &mut oo);
                let h = host::sgetspent_r(cl.as_ptr(), &mut rh, bh.as_mut_ptr().cast(), buflen, &mut oh);
                assert_eq!((a, oo.is_null()), (h, oh.is_null()), "{:?} buflen {buflen}", String::from_utf8_lossy(&line));
                assert_eq!(sp(oo), sp(oh), "{:?}", String::from_utf8_lossy(&line));
                parsed += (!oo.is_null()) as usize;
            }
        }
        unsafe {
            assert_eq!(sp(sgetspent(cl.as_ptr())), sp(host::sgetspent(cl.as_ptr())), "{:?}", String::from_utf8_lossy(&line));
        }
    }
    assert!(parsed > 5000, "only {parsed} lines parsed");
}

#[test]
fn shadow_file_unreadable() {
    // /etc/shadow is not readable for a normal user: lookups fail with the error from open. (The
    // host would go on to nss-systemd, which answers for some users, so it is not compared.)
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    unsafe {
        rusty_libc_core::errno::set(0);
        assert!(getspnam(c"root".as_ptr()).is_null());
        assert_eq!(rusty_libc_core::errno::get(), 13);
        let mut ro: Spwd = core::mem::zeroed();
        let mut buf = [0u8; 1024];
        let mut oo: *mut Spwd = null_mut();
        assert_eq!(getspnam_r(c"root".as_ptr(), &mut ro, buf.as_mut_ptr().cast(), buf.len(), &mut oo), 13);
        assert!(oo.is_null());
        setspent();
        assert!(getspent().is_null());
        assert_eq!(getspent_r(&mut ro, buf.as_mut_ptr().cast(), buf.len(), &mut oo), ENOENT_);
        endspent();
    }
}

// ---------------------------------------------------------------- groups

#[test]
fn group_lookups_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let names = read_names("/etc/group");
    assert!(names.len() > 5);
    let longest = std::fs::read("/etc/group").unwrap().split(|&c| c == b'\n').map(|l| l.len()).max().unwrap();
    for (name, gid) in &names {
        let cn = cs(name);
        for len in [0usize, 5, 20, 100, 400, 1024, 4096, longest + 3, longest + 100] {
            let mut bo = vec![0u8; len.max(1)];
            let mut bh = vec![0u8; len.max(1)];
            let (mut ro, mut rh): (*mut Group, *mut Group) = (null_mut(), null_mut());
            let mut so: Group = unsafe { core::mem::zeroed() };
            let mut sh: Group = unsafe { core::mem::zeroed() };
            unsafe {
                rusty_libc_core::errno::set(77);
                hset_errno(77);
                let a = getgrnam_r(cn.as_ptr(), &mut so, bo.as_mut_ptr().cast(), len, &mut ro);
                let h = host::getgrnam_r(cn.as_ptr(), &mut sh, bh.as_mut_ptr().cast(), len, &mut rh);
                assert_eq!((a, ro.is_null(), rusty_libc_core::errno::get()), (h, rh.is_null(), herrno()), "getgrnam_r {:?} len {len}", String::from_utf8_lossy(name));
                assert_eq!(gr(ro), gr(rh), "getgrnam_r {:?} len {len}", String::from_utf8_lossy(name));
                let a = getgrgid_r(*gid, &mut so, bo.as_mut_ptr().cast(), len, &mut ro);
                let h = host::getgrgid_r(*gid, &mut sh, bh.as_mut_ptr().cast(), len, &mut rh);
                assert_eq!((a, ro.is_null()), (h, rh.is_null()), "getgrgid_r {gid} len {len}");
                assert_eq!(gr(ro), gr(rh), "getgrgid_r {gid} len {len}");
            }
        }
        unsafe {
            assert_eq!(gr(getgrnam(cn.as_ptr())), gr(host::getgrnam(cn.as_ptr())));
            assert_eq!(gr(getgrgid(*gid)), gr(host::getgrgid(*gid)));
        }
    }
    unsafe {
        let mut so: Group = core::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut ro: *mut Group = null_mut();
        assert_eq!(getgrnam_r(c"no-such-group-xyz".as_ptr(), &mut so, buf.as_mut_ptr().cast(), buf.len(), &mut ro), 0);
        assert!(ro.is_null());
    }
}

#[test]
fn group_enumeration_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut ours = vec![];
    unsafe {
        setgrent();
        loop {
            let p = getgrent();
            if p.is_null() {
                break;
            }
            ours.push(gr(p).unwrap());
        }
        endgrent();
    }
    assert!(ours.len() >= read_names("/etc/group").len());
    let mut hostv = vec![];
    unsafe {
        host::setgrent();
        for _ in 0..ours.len() {
            let p = host::getgrent();
            if p.is_null() {
                break;
            }
            hostv.push(gr(p).unwrap());
        }
        host::endgrent();
    }
    assert_eq!(ours, hostv);
}

#[test]
fn getgrouplist_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let users = read_names("/etc/passwd");
    let mut with_groups = 0;
    for (name, _) in &users {
        let cn = cs(name);
        for ng in [0, 1, 2, 3, 5, 100] {
            for basegid in [0u32, 1000, 10] {
                let mut ga = vec![0u32; ng.max(1)];
                let mut gh = vec![0u32; ng.max(1)];
                let (mut na, mut nh) = (ng as c_int, ng as c_int);
                unsafe {
                    let a = getgrouplist(cn.as_ptr(), basegid, ga.as_mut_ptr(), &mut na);
                    let h = host::getgrouplist(cn.as_ptr(), basegid, gh.as_mut_ptr(), &mut nh);
                    assert_eq!((a, na), (h, nh), "getgrouplist {:?} gid {basegid} n {ng}", String::from_utf8_lossy(name));
                    let k = (na as usize).min(ng);
                    assert_eq!(ga[..k], gh[..k], "getgrouplist {:?} gid {basegid} n {ng}", String::from_utf8_lossy(name));
                    with_groups += (na > 1) as usize;
                }
            }
        }
    }
    assert!(with_groups > 0, "no user in /etc/group has extra groups here; the test saw nothing");
}

// ---------------------------------------------------------------- shells and login

#[test]
fn usershells_match_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let mut ours = vec![];
        loop {
            let p = getusershell();
            if p.is_null() {
                break;
            }
            ours.push(CStr::from_ptr(p).to_bytes().to_vec());
        }
        let mut hostv = vec![];
        loop {
            let p = host::getusershell();
            if p.is_null() {
                break;
            }
            hostv.push(CStr::from_ptr(p).to_bytes().to_vec());
        }
        assert!(!ours.is_empty());
        assert_eq!(ours, hostv);
        // after the end it keeps returning NULL until setusershell
        assert!(getusershell().is_null());
        setusershell();
        host::setusershell();
        assert_eq!(CStr::from_ptr(getusershell()), CStr::from_ptr(host::getusershell()));
        endusershell();
        host::endusershell();
        assert_eq!(CStr::from_ptr(getusershell()), CStr::from_ptr(host::getusershell()));
        endusershell();
        host::endusershell();
    }
}

#[test]
fn getlogin_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        rusty_libc_core::errno::set(0);
        hset_errno(0);
        let a = getlogin();
        let h = host::getlogin();
        assert_eq!(a.is_null(), h.is_null());
        if !a.is_null() {
            assert_eq!(CStr::from_ptr(a), CStr::from_ptr(h));
        } else {
            assert_eq!(rusty_libc_core::errno::get(), herrno());
        }
        for len in [0usize, 1, 2, 3, 4, 5, 6, 8, 33, 100] {
            let mut ba = vec![0xaau8; len.max(1)];
            let mut bh = vec![0xaau8; len.max(1)];
            rusty_libc_core::errno::set(0);
            hset_errno(0);
            let ra = getlogin_r(ba.as_mut_ptr().cast(), len);
            let rh = host::getlogin_r(bh.as_mut_ptr().cast(), len);
            assert_eq!(ra, rh, "getlogin_r len {len}");
            if ra == 0 {
                assert_eq!(ba, bh);
            }
        }
    }
}

#[test]
fn lckpwdf_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if unsafe { libc::geteuid() } == 0 {
        return; // would really lock /etc/.pwd.lock
    }
    unsafe {
        rusty_libc_core::errno::set(0);
        hset_errno(0);
        let a = lckpwdf();
        let h = host::lckpwdf();
        assert_eq!((a, rusty_libc_core::errno::get()), (h, herrno()));
        assert_eq!(ulckpwdf(), host::ulckpwdf());
    }
}

#[test]
fn rust_api_lookups() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = [0u8; 2048];
    let root = getpwnam_buf(b"root", &mut buf).unwrap().unwrap();
    assert_eq!(root.uid, 0);
    assert_eq!(root.name, b"root");
    let mut buf2 = [0u8; 2048];
    let by_id = getpwuid_buf(0, &mut buf2).unwrap().unwrap();
    assert_eq!(by_id.name, b"root");
    assert!(getpwnam_buf(b"no-such-user-xyz", &mut buf).unwrap().is_none());
    let mut tiny = [0u8; 4];
    assert_eq!(getpwnam_buf(b"root", &mut tiny).unwrap_err(), 34);
    let mut gbuf = [0u8; 2048];
    let g = getgrgid_buf(0, &mut gbuf).unwrap().unwrap();
    assert_eq!(g.name, b"root");
    let mut gbuf2 = [0u8; 2048];
    let wheel = getgrnam_buf(b"wheel", &mut gbuf2).unwrap();
    if let Some(w) = wheel {
        assert_eq!(w.gid, 10);
        let _ = w.members().count();
    }
}

// ---------------------------------------------------------------- utmp route of getlogin

unsafe extern "C" {
    fn utmpname(path: *const c_char) -> c_int;
    fn setutent();
    fn endutent();
    fn getutline(ut: *const u8) -> *const u8;
}

fn utmp_record(kind: i16, line: &[u8], user: &[u8]) -> [u8; 384] {
    let mut r = [0u8; 384];
    r[0..2].copy_from_slice(&kind.to_le_bytes());
    r[8..8 + line.len()].copy_from_slice(line);
    r[44..44 + user.len()].copy_from_slice(user);
    r
}

#[test]
fn utmp_lookup_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmpfile_path("utmp");
    let mut data = vec![];
    data.extend(utmp_record(2, b"~", b"reboot")); // BOOT_TIME: never matches
    data.extend(utmp_record(7, b"pts/0", b"alice"));
    data.extend(utmp_record(8, b"pts/1", b"dead")); // DEAD_PROCESS: skipped
    data.extend(utmp_record(6, b"tty1", b"LOGIN"));
    data.extend(utmp_record(7, b"pts/1", b"bob"));
    data.extend(utmp_record(7, b"pts/0", b"carol")); // second entry for pts/0: the first wins
    data.extend(utmp_record(7, b"pts/12345678901234567890123456789", b"longline"));
    data.extend(utmp_record(7, b"pts/9", b"abcdefghijklmnopqrstuvwxyz012345")); // 32-byte name, no NUL
    std::fs::write(&path, &data).unwrap();
    let cpath = CString::new(path.clone()).unwrap();
    for line in ["pts/0", "pts/1", "tty1", "~", "pts/2", "pts/12345678901234567890123456789", "pts/9", "pts/"] {
        let mut want = [0u8; 384];
        want[8..8 + line.len()].copy_from_slice(line.as_bytes());
        let host_user = unsafe {
            utmpname(cpath.as_ptr());
            setutent();
            let p = getutline(want.as_ptr());
            let r = if p.is_null() {
                None
            } else {
                let name = core::slice::from_raw_parts(p.add(44), 32);
                Some(name[..name.iter().position(|&c| c == 0).unwrap_or(32)].to_vec())
            };
            endutent();
            r
        };
        let mut out = [0u8; 64];
        let rc = utmp_user_for_line(&cpath, line.as_bytes(), &mut out);
        let ours = if rc == 0 { Some(out[..out.iter().position(|&c| c == 0).unwrap()].to_vec()) } else { None };
        assert_eq!(ours, host_user, "line {line:?}");
        if ours.is_none() {
            assert_eq!(rc, 2, "not found is ENOENT");
        }
    }
    // a name that does not fit
    let mut small = [0u8; 3];
    assert_eq!(utmp_user_for_line(&cpath, b"pts/1", &mut small), 34);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn initgroups_failure_matches_host() {
    // setgroups needs privilege: as a normal user both fail with the same errno
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    unsafe extern "C" {
        #[link_name = "initgroups"]
        fn host_initgroups(user: *const c_char, group: u32) -> c_int;
    }
    for user in [c"root", c"adam", c"nosuchuser-xyz"] {
        unsafe {
            rusty_libc_core::errno::set(0);
            hset_errno(0);
            let a = initgroups(user.as_ptr(), 1000);
            let h = host_initgroups(user.as_ptr(), 1000);
            assert_eq!((a, rusty_libc_core::errno::get()), (h, herrno()), "{user:?}");
        }
    }
}

// ---------------------------------------------------------------- shadow groups (gshadow.h)

#[derive(Debug, PartialEq)]
struct SgRec {
    namp: Bytes,
    passwd: Bytes,
    adm: Option<Vec<Vec<u8>>>,
    mem: Option<Vec<Vec<u8>>>,
}

fn list(l: *mut *mut c_char) -> Option<Vec<Vec<u8>>> {
    if l.is_null() {
        return None;
    }
    let mut v = vec![];
    let mut i = 0;
    unsafe {
        while !(*l.add(i)).is_null() {
            v.push(CStr::from_ptr(*l.add(i)).to_bytes().to_vec());
            i += 1;
        }
    }
    Some(v)
}

fn sg(p: *const Sgrp) -> Option<SgRec> {
    if p.is_null() {
        return None;
    }
    let g = unsafe { &*p };
    Some(SgRec { namp: b(g.sg_namp), passwd: b(g.sg_passwd), adm: list(g.sg_adm), mem: list(g.sg_mem) })
}

fn gen_sg_line(r: &mut Rng) -> Vec<u8> {
    let lists = ["", "a", "a,b", "a, b ,c", ",a,,b,", " ", "adam,wheel,root", "x,y,z,w,v,u,t,s,r,q,p,o,n,m,l,k", "a b", "a:b", "::"];
    let names = ["wheel", "g", "+", "-", "+@x", "", "name", "#c", "-grp"];
    match r.below(10) {
        0 => return b"# a comment".to_vec(),
        1 => return b"".to_vec(),
        _ => {}
    }
    let mut l = String::new();
    if r.chance(10) {
        l.push(' ');
    }
    l.push_str(names[r.below(names.len())]);
    let nf = r.below(5);
    for i in 0..nf {
        l.push(':');
        if i >= 1 {
            if r.chance(5) {
                for k in 0..(20 + r.below(40)) {
                    if k > 0 {
                        l.push(',');
                    }
                    l.push_str(&format!("member{k}"));
                }
            } else {
                l.push_str(lists[r.below(lists.len())]);
            }
        } else {
            l.push_str(["!", "", "*", "$6$salt$h"][r.below(4)]);
        }
    }
    if r.chance(5) {
        l.push('\r');
    }
    l.into_bytes()
}

stream_test!(fgetsgent_r_matches_host, gen_sg_line, Sgrp, fgetsgent_r, fgetsgent_r, sg, "fgetsg", 1500);

#[test]
fn sgetsgent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0x5a5a_1234);
    let mut parsed = 0;
    for _ in 0..20000 {
        let line = gen_sg_line(&mut r);
        let cl = CString::new(line.clone()).unwrap();
        for buflen in [8usize, 30, 80, 200, 1024] {
            let mut bo = vec![0u8; buflen];
            let mut bh = vec![0u8; buflen];
            let mut ro: Sgrp = unsafe { core::mem::zeroed() };
            let mut rh: Sgrp = unsafe { core::mem::zeroed() };
            let (mut oo, mut oh): (*mut Sgrp, *mut Sgrp) = (null_mut(), null_mut());
            unsafe {
                rusty_libc_core::errno::set(0);
                hset_errno(0);
                let a = sgetsgent_r(cl.as_ptr(), &mut ro, bo.as_mut_ptr().cast(), buflen, &mut oo);
                let h = host::sgetsgent_r(cl.as_ptr(), &mut rh, bh.as_mut_ptr().cast(), buflen, &mut oh);
                assert_eq!((a, oo.is_null()), (h, oh.is_null()), "{:?} buflen {buflen}", String::from_utf8_lossy(&line));
                assert_eq!(sg(oo), sg(oh), "{:?}", String::from_utf8_lossy(&line));
                parsed += (!oo.is_null()) as usize;
            }
        }
        unsafe {
            assert_eq!(sg(sgetsgent(cl.as_ptr())), sg(host::sgetsgent(cl.as_ptr())), "{:?}", String::from_utf8_lossy(&line));
        }
    }
    assert!(parsed > 5000, "only {parsed} lines parsed");
}

#[test]
fn fgetsgent_nonreentrant_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = Rng(0xabc1);
    let path = tmpfile_path("fget-sg");
    let cpath = CString::new(path.clone()).unwrap();
    for _ in 0..300 {
        let mut data = gen_file(&mut r, gen_sg_line);
        data.extend(b"\nbig:!:");
        for k in 0..300 {
            data.extend(format!("a{k},").bytes());
        }
        data.extend(b":");
        for k in 0..300 {
            data.extend(format!("u{k},").bytes());
        }
        data.extend(b"\nnext:x::a\n");
        std::fs::write(&path, &data).unwrap();
        unsafe {
            let fo = rusty_libc_stdio::fopen(cpath.as_ptr(), c"r".as_ptr());
            let fh = host::fopen(cpath.as_ptr(), c"r".as_ptr());
            for _ in 0..12 {
                let a = sg(fgetsgent(fo));
                let h = sg(host::fgetsgent(fh));
                assert_eq!(a, h);
                if a.is_none() {
                    break;
                }
            }
            rusty_libc_stdio::fclose(fo);
            host::fclose(fh);
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn putsgent_matches_host() {
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmpfile_path("putsg");
    let strs: [Option<&CStr>; 7] = [Some(c"wheel"), Some(c"+"), Some(c"a:b"), None, Some(c""), Some(c"line\nbreak"), Some(c"x,y")];
    let one: [*mut c_char; 2] = [c"adam".as_ptr() as *mut c_char, null_mut()];
    let two: [*mut c_char; 3] = [c"adam".as_ptr() as *mut c_char, c"root".as_ptr() as *mut c_char, null_mut()];
    let bad: [*mut c_char; 3] = [c"ad:am".as_ptr() as *mut c_char, c"root".as_ptr() as *mut c_char, null_mut()];
    let bad2: [*mut c_char; 2] = [c"a,b".as_ptr() as *mut c_char, null_mut()];
    let empty: [*mut c_char; 1] = [null_mut()];
    let lists: [*mut *mut c_char; 7] = [null_mut(), one.as_ptr() as *mut _, two.as_ptr() as *mut _, bad.as_ptr() as *mut _, bad2.as_ptr() as *mut _, empty.as_ptr() as *mut _, two.as_ptr() as *mut _];
    let mut r = Rng(17);
    for _ in 0..3000 {
        let pick = |r: &mut Rng| strs[r.below(strs.len())].map_or(null_mut(), |s| s.as_ptr() as *mut c_char);
        let p = Sgrp { sg_namp: pick(&mut r), sg_passwd: pick(&mut r), sg_adm: lists[r.below(lists.len())], sg_mem: lists[r.below(lists.len())] };
        let a = write_ours(|f| unsafe { putsgent(&p, f) }, &path);
        let h = write_host(|f| unsafe { host::putsgent(&p, f) }, &path);
        assert_eq!((a.0, &a.1), (h.0, &h.1), "putsgent {:?}", sg(&p));
        if a.0 != 0 {
            assert_eq!(a.2, h.2);
        }
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn gshadow_file_unreadable() {
    // /etc/gshadow is not readable for a normal user: lookups fail with the error from open.
    let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    unsafe {
        rusty_libc_core::errno::set(0);
        assert!(getsgnam(c"root".as_ptr()).is_null());
        assert_eq!(rusty_libc_core::errno::get(), 13);
        setsgent();
        assert!(getsgent().is_null());
        endsgent();
    }
}
