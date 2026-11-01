//! Users and groups through the C library the process runs on (feature `libc-services`). NSS is a stateful C-library
//! service (nsswitch.conf, loaded modules, nscd/sssd sockets, files cached by the library), so the state rule of
//! FIXLIST #127 sends these lookups through that library's C ABI (rusty-libc's or glibc's `getpwnam_r` ...), never
//! through a second NSS implementation in the face.
//!
//! Every lookup uses the reentrant `_r` form with a buffer owned here, growing it on ERANGE, and copies the strings out
//! before the buffer is dropped. The extern declarations are this crate's own (no `libc` crate dependency).

use crate::errno::Errno;
use core::ffi::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::vec::Vec;

/// glibc's / rusty-libc's `struct passwd` (x86-64).
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

/// glibc's / rusty-libc's `struct group` (x86-64).
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

/// glibc's / rusty-libc's `struct hostent` (x86-64).
#[repr(C)]
struct Hostent {
    h_name: *mut c_char,
    h_aliases: *mut *mut c_char,
    h_addrtype: c_int,
    h_length: c_int,
    h_addr_list: *mut *mut c_char,
}

/// A user database entry, strings copied out of the C library's buffer (bytes, no trailing NUL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdEntry {
    /// pw_name.
    pub name: Vec<u8>,
    /// pw_uid.
    pub uid: u32,
    /// pw_gid.
    pub gid: u32,
    /// pw_gecos.
    pub gecos: Vec<u8>,
    /// pw_dir.
    pub dir: Vec<u8>,
    /// pw_shell.
    pub shell: Vec<u8>,
}

/// A group database entry (bytes, no trailing NUL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    /// gr_name.
    pub name: Vec<u8>,
    /// gr_gid.
    pub gid: u32,
    /// gr_mem: the member user names.
    pub members: Vec<Vec<u8>>,
}

const FIRST_BUF: usize = 1024;
/// The largest buffer tried before giving up with ERANGE (glibc's own getpwnam grows without a limit; 16 MiB is far
/// beyond any real entry and stops a broken NSS module from exhausting memory).
const MAX_BUF: usize = 16 << 20;

/// The bytes of a C string inside the lookup buffer (empty for NULL).
///
/// # Safety
/// `p` is NULL or points to a NUL-terminated string that stays valid for the call.
unsafe fn bytes(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: non-NULL and NUL-terminated by the caller's contract.
    unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// Run one `_r` lookup with a growing buffer: `call(buf)` makes the call with `buf` and returns its error number and,
/// when found, the entry copied out of `buf` (inside the closure, while the buffer is alive).
fn with_buffer<T>(mut call: impl FnMut(&mut [u8]) -> (c_int, Option<T>)) -> Result<Option<T>, Errno> {
    let mut buf = std::vec![0u8; FIRST_BUF];
    loop {
        match call(&mut buf) {
            (0, found) => return Ok(found),
            // ENOENT is also "not found" (getpwnam(3) NOTES), as some NSS modules report it
            (2, _) => return Ok(None),
            (34, _) if buf.len() < MAX_BUF => buf.resize(buf.len() * 2, 0), // ERANGE: the buffer was too small
            (e, _) => return Err(Errno(e)),
        }
    }
}

fn passwd_of(p: &Passwd) -> PasswdEntry {
    // The C library set each string field to NULL or to a NUL-terminated string inside the buffer that `with_buffer`
    // keeps alive while this runs.
    PasswdEntry {
        // SAFETY: see above.
        name: unsafe { bytes(p.pw_name) },
        uid: p.pw_uid,
        gid: p.pw_gid,
        // SAFETY: see above.
        gecos: unsafe { bytes(p.pw_gecos) },
        // SAFETY: see above.
        dir: unsafe { bytes(p.pw_dir) },
        // SAFETY: see above.
        shell: unsafe { bytes(p.pw_shell) },
    }
}

fn group_of(g: &Group) -> GroupEntry {
    let mut members = Vec::new();
    if !g.gr_mem.is_null() {
        let mut i = 0;
        loop {
            // SAFETY: gr_mem is a NULL-terminated array of string pointers inside the lookup buffer; `i` never passes
            // the terminating NULL (the loop stops there).
            let m = unsafe { *g.gr_mem.wrapping_add(i) };
            if m.is_null() {
                break;
            }
            // SAFETY: a non-NULL member is a NUL-terminated string inside the buffer.
            members.push(unsafe { bytes(m) });
            i += 1;
        }
    }
    // SAFETY: as in `passwd_of`.
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
            // SAFETY: `n` is NUL-terminated; `pw`, `res` and `buf` (`l` bytes) are live and writable; the library
            // writes the entry into `pw`, its strings into `buf`, and `&pw` or NULL into `res`.
            Key::Name(n) => unsafe { getpwnam_r(n.as_ptr(), &mut pw, b, l, &mut res) },
            // SAFETY: as above, with a plain uid.
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
            // SAFETY: as in `passwd`, for `struct group`.
            Key::Name(n) => unsafe { getgrnam_r(n.as_ptr(), &mut gr, b, l, &mut res) },
            // SAFETY: as above, with a plain gid.
            Key::Id(g) => unsafe { getgrgid_r(g, &mut gr, b, l, &mut res) },
        };
        (e, (e == 0 && !res.is_null()).then(|| group_of(&gr)))
    })
}

/// getpwnam_r(3) through the running C library. `Ok(None)`: no such user (also for a name containing a NUL byte,
/// which no entry can have).
pub fn user_by_name(name: &[u8]) -> Result<Option<PasswdEntry>, Errno> {
    let Ok(c) = CString::new(name) else { return Ok(None) };
    passwd(Key::Name(&c))
}

/// getpwuid_r(3) through the running C library. `Ok(None)`: no such user.
pub fn user_by_uid(uid: u32) -> Result<Option<PasswdEntry>, Errno> {
    passwd(Key::Id(uid))
}

/// getgrnam_r(3) through the running C library. `Ok(None)`: no such group (or a name with a NUL byte).
pub fn group_by_name(name: &[u8]) -> Result<Option<GroupEntry>, Errno> {
    let Ok(c) = CString::new(name) else { return Ok(None) };
    group(Key::Name(&c))
}

/// getgrgid_r(3) through the running C library. `Ok(None)`: no such group.
pub fn group_by_gid(gid: u32) -> Result<Option<GroupEntry>, Errno> {
    group(Key::Id(gid))
}

/// getgrouplist(3) through the running C library: `group` plus every group whose member list names `user`, as
/// initgroups(3) would set them (duplicates of `group` removed by the library). EINVAL for a name with a NUL byte.
pub fn group_list(user: &[u8], group: u32) -> Result<Vec<u32>, Errno> {
    let c = CString::new(user).map_err(|_| Errno::EINVAL)?;
    let mut groups: Vec<u32> = std::vec![0; 32];
    loop {
        let mut n = c_int::try_from(groups.len()).map_err(|_| Errno(34))?;
        // SAFETY: `c` is NUL-terminated; the library writes at most `n` (= groups.len()) gids into `groups` and the
        // number found (or needed) into the local `n`.
        let r = unsafe { getgrouplist(c.as_ptr(), group, groups.as_mut_ptr(), &mut n) };
        let n = usize::try_from(n).unwrap_or(0);
        if r >= 0 {
            groups.truncate(n.min(groups.len()));
            return Ok(groups);
        }
        // -1: too small; `n` is the number needed (glibc and rusty-libc). Grow to that, at least double, with a cap.
        let want = n.max(groups.len() * 2);
        if want > 1 << 20 {
            return Err(Errno(34));
        }
        groups.resize(want, 0);
    }
}

/// gethostbyname_r(3) through the running C library (the hosts database: /etc/hosts, DNS, ... as nsswitch.conf says):
/// the first IPv4 address of `name`, its first `min(4, h_length)` bytes (zero-padded), as glibc's gethostid copies it.
/// `None` when the name is not found or the lookup fails (also for a name with a NUL byte); the buffer grows on
/// ERANGE up to 16 MiB.
pub fn host_first_address(name: &[u8]) -> Option<[u8; 4]> {
    let c = CString::new(name).ok()?;
    with_buffer(|buf| {
        let mut h = Hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
        let mut res: *mut Hostent = core::ptr::null_mut();
        let mut herr: c_int = 0;
        let (b, l) = (buf.as_mut_ptr().cast::<c_char>(), buf.len());
        // SAFETY: `c` is NUL-terminated; `h`, `res`, `herr` and `buf` (`l` bytes) are live and writable; the library
        // writes the entry into `h`, its data into `buf`, and `&h` or NULL into `res`.
        let e = unsafe { gethostbyname_r(c.as_ptr(), &mut h, b, l, &mut res, &mut herr) };
        if e == 34 {
            return (34, None); // ERANGE: grow
        }
        if e != 0 || res.is_null() || h.h_addr_list.is_null() {
            return (0, None);
        }
        // SAFETY: h_addr_list is a NULL-terminated vector inside `buf`; element 0 exists (it is the terminator at worst).
        let a = unsafe { *h.h_addr_list };
        if a.is_null() {
            return (0, None);
        }
        let n = usize::try_from(h.h_length).unwrap_or(0).min(4);
        let mut out = [0u8; 4];
        // SAFETY: a non-NULL address entry points to h_length bytes inside `buf`; at most 4 of them are read.
        out[..n].copy_from_slice(unsafe { core::slice::from_raw_parts(a.cast::<u8>(), n) });
        (0, Some(out))
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_missing() {
        let r = user_by_uid(0).unwrap().unwrap();
        assert_eq!((r.name.as_slice(), r.uid, r.gid), (&b"root"[..], 0, 0));
        assert_eq!(user_by_name(b"root").unwrap(), Some(r));
        assert_eq!(user_by_name(b"no-such-user-rlrs").unwrap(), None);
        assert_eq!(user_by_name(b"ro\0ot").unwrap(), None);
        let g = group_by_gid(0).unwrap().unwrap();
        assert_eq!(g.name, b"root");
        assert_eq!(group_by_name(b"root").unwrap(), Some(g));
        assert_eq!(group_by_name(b"no-such-group-rlrs").unwrap(), None);
        assert_eq!(group_list(b"root", 0).unwrap()[0], 0);
        assert_eq!(group_list(b"r\0", 0), Err(Errno::EINVAL));
        assert_eq!(host_first_address(b"localhost"), Some([127, 0, 0, 1]));
        assert_eq!(host_first_address(b"no-such-host-rlrs.invalid"), None);
    }

    #[test]
    fn buffer_growth() {
        let mut calls = 0;
        let r = with_buffer(|buf| {
            calls += 1;
            if buf.len() < 4 * FIRST_BUF { (34, None) } else { (0, Some(buf.len())) }
        });
        assert_eq!(r, Ok(Some(4 * FIRST_BUF)));
        assert_eq!(calls, 3);
        assert_eq!(with_buffer(|_| (34, None::<()>)), Err(Errno(34)));
        assert_eq!(with_buffer(|_| (5, None::<()>)), Err(Errno(5)));
        assert_eq!(with_buffer(|_| (2, None::<()>)), Ok(None));
        assert_eq!(with_buffer(|_| (0, None::<()>)), Ok(None));
    }
}
