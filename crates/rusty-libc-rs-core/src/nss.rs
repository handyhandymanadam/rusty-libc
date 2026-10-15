use crate::errno::Errno;
use core::ffi::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::vec::Vec;

#[repr(C)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: u32,
    pw_gid: u32,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
}

#[repr(C)]
struct Group {
    gr_name: *mut c_char,
    gr_passwd: *mut c_char,
    gr_gid: u32,
    gr_mem: *mut *mut c_char,
}

unsafe extern "C" {
    fn getpwnam_r(name: *const c_char, pwd: *mut Passwd, buf: *mut c_char, len: usize, result: *mut *mut Passwd) -> c_int;
    fn getpwuid_r(uid: u32, pwd: *mut Passwd, buf: *mut c_char, len: usize, result: *mut *mut Passwd) -> c_int;
    fn getgrnam_r(name: *const c_char, grp: *mut Group, buf: *mut c_char, len: usize, result: *mut *mut Group) -> c_int;
    fn getgrgid_r(gid: u32, grp: *mut Group, buf: *mut c_char, len: usize, result: *mut *mut Group) -> c_int;
    fn getgrouplist(user: *const c_char, group: u32, groups: *mut u32, ngroups: *mut c_int) -> c_int;
    fn gethostbyname_r(name: *const c_char, ret: *mut Hostent, buf: *mut c_char, len: usize, result: *mut *mut Hostent, h_errnop: *mut c_int) -> c_int;
}

#[repr(C)]
struct Hostent {
    h_name: *mut c_char,
    h_aliases: *mut *mut c_char,
    h_addrtype: c_int,
    h_length: c_int,
    h_addr_list: *mut *mut c_char,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub gecos: Vec<u8>,
    pub dir: Vec<u8>,
    pub shell: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: Vec<u8>,
    pub gid: u32,
    pub members: Vec<Vec<u8>>,
}

const FIRST_BUF: usize = 1024;
const MAX_BUF: usize = 16 << 20;

unsafe fn bytes(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

fn with_buffer<T>(mut call: impl FnMut(&mut [u8]) -> (c_int, Option<T>)) -> Result<Option<T>, Errno> {
    let mut buf = std::vec![0u8; FIRST_BUF];
    loop {
        match call(&mut buf) {
            (0, found) => return Ok(found),
            (2, _) => return Ok(None),
            (34, _) if buf.len() < MAX_BUF => buf.resize(buf.len() * 2, 0),
            (e, _) => return Err(Errno(e)),
        }
    }
}

fn passwd_of(p: &Passwd) -> PasswdEntry {
    PasswdEntry {
        name: unsafe { bytes(p.pw_name) },
        uid: p.pw_uid,
        gid: p.pw_gid,
        gecos: unsafe { bytes(p.pw_gecos) },
        dir: unsafe { bytes(p.pw_dir) },
        shell: unsafe { bytes(p.pw_shell) },
    }
}

fn group_of(g: &Group) -> GroupEntry {
    let mut members = Vec::new();
    if !g.gr_mem.is_null() {
        let mut i = 0;
        loop {
            let m = unsafe { *g.gr_mem.wrapping_add(i) };
            if m.is_null() {
                break;
            }
            members.push(unsafe { bytes(m) });
            i += 1;
        }
    }
    GroupEntry { name: unsafe { bytes(g.gr_name) }, gid: g.gr_gid, members }
}

const NO_PASSWD: Passwd = Passwd {
    pw_name: core::ptr::null_mut(),
    pw_passwd: core::ptr::null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: core::ptr::null_mut(),
    pw_dir: core::ptr::null_mut(),
    pw_shell: core::ptr::null_mut(),
};
const NO_GROUP: Group = Group { gr_name: core::ptr::null_mut(), gr_passwd: core::ptr::null_mut(), gr_gid: 0, gr_mem: core::ptr::null_mut() };

enum Key<'a> {
    Name(&'a CStr),
    Id(u32),
}

fn passwd(key: Key<'_>) -> Result<Option<PasswdEntry>, Errno> {
    with_buffer(|buf| {
        let mut pw = NO_PASSWD;
        let mut res: *mut Passwd = core::ptr::null_mut();
        let (b, l) = (buf.as_mut_ptr().cast::<c_char>(), buf.len());
        let e = match key {
            Key::Name(n) => unsafe { getpwnam_r(n.as_ptr(), &mut pw, b, l, &mut res) },
            Key::Id(u) => unsafe { getpwuid_r(u, &mut pw, b, l, &mut res) },
        };
        (e, (e == 0 && !res.is_null()).then(|| passwd_of(&pw)))
    })
}

fn group(key: Key<'_>) -> Result<Option<GroupEntry>, Errno> {
    with_buffer(|buf| {
        let mut gr = NO_GROUP;
        let mut res: *mut Group = core::ptr::null_mut();
        let (b, l) = (buf.as_mut_ptr().cast::<c_char>(), buf.len());
        let e = match key {
            Key::Name(n) => unsafe { getgrnam_r(n.as_ptr(), &mut gr, b, l, &mut res) },
            Key::Id(g) => unsafe { getgrgid_r(g, &mut gr, b, l, &mut res) },
        };
        (e, (e == 0 && !res.is_null()).then(|| group_of(&gr)))
    })
}

pub fn user_by_name(name: &[u8]) -> Result<Option<PasswdEntry>, Errno> {
    let Ok(c) = CString::new(name) else { return Ok(None) };
    passwd(Key::Name(&c))
}

pub fn user_by_uid(uid: u32) -> Result<Option<PasswdEntry>, Errno> {
    passwd(Key::Id(uid))
}

pub fn group_by_name(name: &[u8]) -> Result<Option<GroupEntry>, Errno> {
    let Ok(c) = CString::new(name) else { return Ok(None) };
    group(Key::Name(&c))
}

pub fn group_by_gid(gid: u32) -> Result<Option<GroupEntry>, Errno> {
    group(Key::Id(gid))
}

pub fn group_list(user: &[u8], group: u32) -> Result<Vec<u32>, Errno> {
    let c = CString::new(user).map_err(|_| Errno::EINVAL)?;
    let mut groups: Vec<u32> = std::vec![0; 32];
    loop {
        let mut n = c_int::try_from(groups.len()).map_err(|_| Errno(34))?;
        let r = unsafe { getgrouplist(c.as_ptr(), group, groups.as_mut_ptr(), &mut n) };
        let n = usize::try_from(n).unwrap_or(0);
        if r >= 0 {
            groups.truncate(n.min(groups.len()));
            return Ok(groups);
        }
        let want = n.max(groups.len() * 2);
        if want > 1 << 20 {
            return Err(Errno(34));
        }
        groups.resize(want, 0);
    }
}

pub fn host_first_address(name: &[u8]) -> Option<[u8; 4]> {
    let c = CString::new(name).ok()?;
    with_buffer(|buf| {
        let mut h = Hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
        let mut res: *mut Hostent = core::ptr::null_mut();
        let mut herr: c_int = 0;
        let (b, l) = (buf.as_mut_ptr().cast::<c_char>(), buf.len());
        let e = unsafe { gethostbyname_r(c.as_ptr(), &mut h, b, l, &mut res, &mut herr) };
        if e == 34 {
            return (34, None);
        }
        if e != 0 || res.is_null() || h.h_addr_list.is_null() {
            return (0, None);
        }
        let a = unsafe { *h.h_addr_list };
        if a.is_null() {
            return (0, None);
        }
        let n = usize::try_from(h.h_length).unwrap_or(0).min(4);
        let mut out = [0u8; 4];
        out[..n].copy_from_slice(unsafe { core::slice::from_raw_parts(a.cast::<u8>(), n) });
        (0, Some(out))
    })
    .ok()
    .flatten()
}

