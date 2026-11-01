//! Users and groups (`rusty_libc_rs::users`), looked up through the C library the process runs on (rusty-libc or
//! glibc): its NSS (nsswitch.conf, files, sssd, systemd-userdb ...) is stateful, so the face does not keep a second
//! copy (FIXLIST #127 state rule). The C calls are in rusty-libc-rs-core's `nss` module (feature `libc-services`).
//! Replaces the `uzers` crate's lookups: `get_user_by_name` -> [`user_by_name`], `get_user_by_uid` -> [`user_by_uid`],
//! `get_current_username` -> [`current_user_name`], `get_group_by_*` -> [`group_by_name`]/[`group_by_gid`],
//! `get_user_groups` -> [`group_list`].

use rusty_libc_rs_core::nss;
use rustix::io;
use rustix::process::{Gid, Uid};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

/// A user database entry (`struct passwd` without the password field, which is "x" or "*" on any shadowed system).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// Login name (pw_name).
    pub name: OsString,
    /// User id (pw_uid).
    pub uid: Uid,
    /// Primary group id (pw_gid).
    pub gid: Gid,
    /// The GECOS field: full name and other comma-separated information (pw_gecos).
    pub gecos: OsString,
    /// Home directory (pw_dir).
    pub home: PathBuf,
    /// Login shell (pw_shell; may be empty, which means /bin/sh to login(1)).
    pub shell: PathBuf,
}

/// A group database entry (`struct group` without the password field).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Group name (gr_name).
    pub name: OsString,
    /// Group id (gr_gid).
    pub gid: Gid,
    /// The users listed as members (gr_mem; users whose primary group this is are usually not listed).
    pub members: Vec<OsString>,
}

fn os(v: Vec<u8>) -> OsString {
    OsString::from_vec(v)
}

/// An id from the database; -1 (u32::MAX) is "no id" in the C API and rustix's `Uid`/`Gid` refuse it: such an entry
/// is reported as EINVAL.
fn uid(v: u32) -> io::Result<Uid> {
    if v == u32::MAX { Err(io::Errno::INVAL) } else { Ok(Uid::from_raw(v)) }
}

fn gid(v: u32) -> io::Result<Gid> {
    if v == u32::MAX { Err(io::Errno::INVAL) } else { Ok(Gid::from_raw(v)) }
}

fn user(e: Option<nss::PasswdEntry>) -> io::Result<Option<User>> {
    let Some(e) = e else { return Ok(None) };
    Ok(Some(User {
        uid: uid(e.uid)?,
        gid: gid(e.gid)?,
        name: os(e.name),
        gecos: os(e.gecos),
        home: os(e.dir).into(),
        shell: os(e.shell).into(),
    }))
}

fn group(e: Option<nss::GroupEntry>) -> io::Result<Option<Group>> {
    let Some(e) = e else { return Ok(None) };
    Ok(Some(Group { gid: gid(e.gid)?, name: os(e.name), members: e.members.into_iter().map(os).collect() }))
}

/// getpwnam_r(3): the user named `name`; `Ok(None)` when there is none (also for a name with a NUL byte).
pub fn user_by_name(name: impl AsRef<OsStr>) -> io::Result<Option<User>> {
    user(nss::user_by_name(name.as_ref().as_bytes()).map_err(crate::errno)?)
}

/// getpwuid_r(3): the user with id `uid`; `Ok(None)` when there is none.
pub fn user_by_uid(uid: Uid) -> io::Result<Option<User>> {
    user(nss::user_by_uid(uid.as_raw()).map_err(crate::errno)?)
}

/// The login name of the calling process's real user id (getpwuid_r(getuid())), as `uzers::get_current_username` and
/// bash's `$USER` fallback; `Ok(None)` when the uid has no entry (common in containers).
pub fn current_user_name() -> io::Result<Option<OsString>> {
    Ok(user_by_uid(rustix::process::getuid())?.map(|u| u.name))
}

/// getgrnam_r(3): the group named `name`; `Ok(None)` when there is none (also for a name with a NUL byte).
pub fn group_by_name(name: impl AsRef<OsStr>) -> io::Result<Option<Group>> {
    group(nss::group_by_name(name.as_ref().as_bytes()).map_err(crate::errno)?)
}

/// getgrgid_r(3): the group with id `gid`; `Ok(None)` when there is none.
pub fn group_by_gid(gid: Gid) -> io::Result<Option<Group>> {
    group(nss::group_by_gid(gid.as_raw()).map_err(crate::errno)?)
}

/// getgrouplist(3): the groups `user` belongs to, `primary` (normally the user's `gid`) first, then every group whose
/// member list names `user`: the list initgroups(3) would install, what `id -G user` prints. EINVAL for a name with a
/// NUL byte. An unknown user gets just `[primary]`.
pub fn group_list(user: impl AsRef<OsStr>, primary: Gid) -> io::Result<Vec<Gid>> {
    let v = nss::group_list(user.as_ref().as_bytes(), primary.as_raw()).map_err(crate::errno)?;
    v.into_iter().map(gid).collect()
}
