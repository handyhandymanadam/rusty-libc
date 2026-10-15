use rusty_libc_rs_core::nss;
use rustix::io;
use rustix::process::{Gid, Uid};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: OsString,
    pub uid: Uid,
    pub gid: Gid,
    pub gecos: OsString,
    pub home: PathBuf,
    pub shell: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: OsString,
    pub gid: Gid,
    pub members: Vec<OsString>,
}

fn os(v: Vec<u8>) -> OsString {
    OsString::from_vec(v)
}

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

pub fn user_by_name(name: impl AsRef<OsStr>) -> io::Result<Option<User>> {
    user(nss::user_by_name(name.as_ref().as_bytes()).map_err(crate::errno)?)
}

pub fn user_by_uid(uid: Uid) -> io::Result<Option<User>> {
    user(nss::user_by_uid(uid.as_raw()).map_err(crate::errno)?)
}

pub fn current_user_name() -> io::Result<Option<OsString>> {
    Ok(user_by_uid(rustix::process::getuid())?.map(|u| u.name))
}

pub fn group_by_name(name: impl AsRef<OsStr>) -> io::Result<Option<Group>> {
    group(nss::group_by_name(name.as_ref().as_bytes()).map_err(crate::errno)?)
}

pub fn group_by_gid(gid: Gid) -> io::Result<Option<Group>> {
    group(nss::group_by_gid(gid.as_raw()).map_err(crate::errno)?)
}

pub fn group_list(user: impl AsRef<OsStr>, primary: Gid) -> io::Result<Vec<Gid>> {
    let v = nss::group_list(user.as_ref().as_bytes(), primary.as_raw()).map_err(crate::errno)?;
    v.into_iter().map(gid).collect()
}
