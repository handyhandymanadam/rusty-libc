//! Client for the name service cache daemon (nscd), over its unix socket only.
//!
//! glibc's NSS asks the daemon first for passwd, group, hosts, services and netgroup lookups, and falls back to the
//! nsswitch.conf sources when the daemon cannot answer. This module is that first step, following glibc 2.43
//! (nscd/nscd_helper.c, nscd_getpw_r.c, nscd_getgr_r.c, nscd_gethst_r.c, nscd_getserv_r.c, nscd_getai.c,
//! nscd_initgroups.c, nscd_netgroup.c and the callers in nss/getXXbyYY_r.c, nss/getaddrinfo.c, nss/initgroups.c,
//! nss/getnetgrent_r.c), read as reference and written by hand. Protocol version 2, socket `/var/run/nscd/socket`.
//!
//! Not done, on purpose: the shared-memory databases (`GETFD*` requests, which glibc sends before the socket requests). A
//! real daemon answers every lookup on the socket as well, so the answers are the same; only the speed differs.
//!
//! When to fall back (the functions return `Fallback`, `None`): no daemon, any connect, send or receive failure, no answer
//! within 5 seconds, a short or malformed reply, a daemon that does not cache the database (`found == -1`), the key
//! longer than 1024 bytes, `LOCALDOMAIN` set (hosts), or a database whose sources a program set with
//! `__nss_configure_lookup`. After a failure glibc stops asking for that database for the next 100 calls (`ask` counts
//! them), then tries again; there is no other retry. An answer with `found == 0` is final: "not found", no NSS lookup.
//!
//! Layout of the work: [`wire`] the bytes, [`conn`] the socket, [`reply`] the reply parsers; this file has the per-database
//! flags and one function per lookup that ties them together.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
pub mod conn;
pub mod reply;
pub mod wire;

use crate::{env, nssent};
use conn::{Conn, Source};
use core::sync::atomic::{AtomicI32, Ordering};
use reply::{AddrInfoData, GroupLayout, HostLayout, PasswdLayout, Reply, ServiceLayout};
use wire::Request;

/// `NSS_NSCD_RETRY`: calls to skip the daemon after a failure.
const RETRY: i32 = 100;

/// The databases the daemon caches, each with glibc's `__nss_not_use_nscd_*` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Database {
    Passwd = 0,
    Group = 1,
    Hosts = 2,
    Services = 3,
    Netgroup = 4,
}

/// 0: ask the daemon; 1 to `RETRY`: skip it, counting calls; (glibc's nscd itself sets -1: never asks itself.)
static NOT_USE: [AtomicI32; 5] = [const { AtomicI32::new(0) }; 5];

impl Database {
    /// The name in nsswitch.conf.
    fn name(self) -> &'static [u8] {
        match self {
            Database::Passwd => b"passwd",
            Database::Group => b"group",
            Database::Hosts => b"hosts",
            Database::Services => b"services",
            Database::Netgroup => b"netgroup",
        }
    }

    /// The step every glibc caller makes before asking the daemon: count a call in the skipping period (the flag is reset
    /// after `RETRY` of them) and say whether the daemon is to be asked: flag clear and no `__nss_configure_lookup` for it.
    pub fn enabled(self) -> bool {
        let flag = &NOT_USE[self as usize];
        let mut now = flag.load(Ordering::Relaxed);
        if now > 0 {
            now += 1;
            if now > RETRY {
                now = 0;
            }
            flag.store(now, Ordering::Relaxed);
        }
        now == 0 && nssent::overridden(self.name()).is_none()
    }

    /// The daemon could not be used: skip it for the next `RETRY` calls.
    pub fn disable(self) {
        NOT_USE[self as usize].store(1, Ordering::Relaxed);
    }

    /// The flag's value (for tests).
    pub fn flag(self) -> i32 {
        NOT_USE[self as usize].load(Ordering::Relaxed)
    }

    /// Set the flag (for tests).
    pub fn set_flag(self, value: i32) {
        NOT_USE[self as usize].store(value, Ordering::Relaxed);
    }
}

/// What a lookup through the daemon came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Res<T> {
    /// The record, laid out in the caller's buffer.
    Found(T),
    /// Final "no such record" (return 0, result NULL, errno 0); the `h_errno` the daemon sent (hosts).
    NotFound(i32),
    /// The record does not fit the buffer (`ERANGE`; hosts also set `h_errno` to `NETDB_INTERNAL`).
    Erange,
    /// passwd and group: the record was announced and the data stopped short (return and set `ENOENT`).
    Enoent,
    /// Ask the NSS sources instead.
    Fallback,
}

/// Send `req`, read `header_len` bytes of header, and let `parse` read the rest. Failure to get a header, or a daemon that
/// does not cache the database, disables the daemon for a while.
fn ask<T>(db: Database, req: Request, key: &[u8], header_len: usize, parse: impl FnOnce(&[u8], &mut Conn) -> Reply<T>) -> Res<T> {
    let mut header = [0u8; wire::PASSWD_HEADER];
    let header = &mut header[..header_len];
    let Some(mut conn) = Conn::open(req, key, header) else {
        db.disable();
        return Res::Fallback;
    };
    match parse(header, &mut conn) {
        Reply::Found(layout) => Res::Found(layout),
        Reply::NotFound { error } => Res::NotFound(error),
        Reply::Erange => Res::Erange,
        Reply::Truncated => Res::Enoent,
        Reply::Unusable => Res::Fallback,
        Reply::Disabled => {
            db.disable();
            Res::Fallback
        }
    }
}

/// A key being built: at most `MAXKEYLEN` bytes (a longer one makes the daemon unusable, as in glibc).
struct Key {
    bytes: [u8; wire::MAXKEYLEN + 1],
    len: usize,
    overflow: bool,
}

impl Key {
    fn new() -> Key {
        Key { bytes: [0; wire::MAXKEYLEN + 1], len: 0, overflow: false }
    }

    fn push(&mut self, part: &[u8]) -> &mut Key {
        match self.bytes.get_mut(self.len..self.len + part.len()) {
            Some(dst) if self.len + part.len() <= wire::MAXKEYLEN => {
                dst.copy_from_slice(part);
                self.len += part.len();
            }
            _ => self.overflow = true,
        }
        self
    }

    /// The decimal digits of `value`.
    fn push_decimal(&mut self, mut value: u64) -> &mut Key {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[at..])
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// `ask` with a built key. A key over the limit is a failed `__nscd_open_socket`.
fn ask_key<T>(db: Database, req: Request, key: &Key, header_len: usize, parse: impl FnOnce(&[u8], &mut Conn) -> Reply<T>) -> Res<T> {
    if key.overflow {
        db.disable();
        return Res::Fallback;
    }
    ask(db, req, key.as_bytes(), header_len, parse)
}

/// `getpwnam_r`.
pub fn passwd_by_name(name: &[u8], buf: &mut [u8]) -> Res<PasswdLayout> {
    if !Database::Passwd.enabled() {
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push(name).push(&[0]);
    ask_key(Database::Passwd, Request::PasswdByName, &key, wire::PASSWD_HEADER, |h, c| reply::passwd(h, c, buf))
}

/// `getpwuid_r`.
pub fn passwd_by_uid(uid: u32, buf: &mut [u8]) -> Res<PasswdLayout> {
    if !Database::Passwd.enabled() {
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push_decimal(u64::from(uid)).push(&[0]);
    ask_key(Database::Passwd, Request::PasswdByUid, &key, wire::PASSWD_HEADER, |h, c| reply::passwd(h, c, buf))
}

/// `getgrnam_r`.
pub fn group_by_name(name: &[u8], buf: &mut [u8]) -> Res<GroupLayout> {
    if !Database::Group.enabled() {
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push(name).push(&[0]);
    ask_key(Database::Group, Request::GroupByName, &key, wire::GROUP_HEADER, |h, c| reply::group(h, c, buf))
}

/// `getgrgid_r`.
pub fn group_by_gid(gid: u32, buf: &mut [u8]) -> Res<GroupLayout> {
    if !Database::Group.enabled() {
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push_decimal(u64::from(gid)).push(&[0]);
    ask_key(Database::Group, Request::GroupByGid, &key, wire::GROUP_HEADER, |h, c| reply::group(h, c, buf))
}

/// glibc's `__nss_have_localdomain`: 0 not looked at yet, 1 `LOCALDOMAIN` is set, -1 it is not. Decided once per process.
static HAVE_LOCALDOMAIN: AtomicI32 = AtomicI32::new(0);

/// `LOCALDOMAIN` in the environment makes the daemon unusable for hosts: the resolver's search list is not the daemon's.
fn localdomain_set() -> bool {
    let mut state = HAVE_LOCALDOMAIN.load(Ordering::Relaxed);
    if state == 0 {
        // SAFETY: the library's own environment reader, which tolerates concurrent changes (its contract is the environ array's).
        let set = !unsafe { env::getenv(b"LOCALDOMAIN") }.is_null();
        state = if set { 1 } else { -1 };
        HAVE_LOCALDOMAIN.store(state, Ordering::Relaxed);
    }
    state > 0
}

/// `gethostbyname_r` (`v6` false) and `gethostbyname2_r` with `AF_INET6` (`v6` true; any other family asks as IPv4).
pub fn host_by_name(name: &[u8], v6: bool, buf: &mut [u8]) -> Res<HostLayout> {
    if !Database::Hosts.enabled() {
        return Res::Fallback;
    }
    if localdomain_set() {
        Database::Hosts.disable();
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push(name).push(&[0]);
    let req = if v6 { Request::HostByNameV6 } else { Request::HostByName };
    ask_key(Database::Hosts, req, &key, wire::HOST_HEADER, |h, c| reply::host(h, v6, c, buf))
}

/// `gethostbyaddr_r`: `addr` is the whole address, `family` `AF_INET` (2) or `AF_INET6` (10); other pairs of length and
/// family are not asked (no flag change).
pub fn host_by_addr(addr: &[u8], family: i32, buf: &mut [u8]) -> Res<HostLayout> {
    if !Database::Hosts.enabled() {
        return Res::Fallback;
    }
    let v6 = match (addr.len(), family) {
        (4, 2) => false,
        (16, 10) => true,
        _ => return Res::Fallback,
    };
    if localdomain_set() {
        Database::Hosts.disable();
        return Res::Fallback;
    }
    let mut key = Key::new();
    key.push(addr);
    let req = if v6 { Request::HostByAddrV6 } else { Request::HostByAddr };
    ask_key(Database::Hosts, req, &key, wire::HOST_HEADER, |h, c| reply::host(h, v6, c, buf))
}

/// The key of a services request: `crit/proto` and a NUL (`crit/` for any protocol).
fn service_key(crit: &[u8], proto: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.push(crit).push(b"/").push(proto.unwrap_or(b"")).push(&[0]);
    key
}

/// `getservbyname_r`; `proto` None asks for any protocol.
pub fn service_by_name(name: &[u8], proto: Option<&[u8]>, buf: &mut [u8]) -> Res<ServiceLayout> {
    if !Database::Services.enabled() {
        return Res::Fallback;
    }
    let key = service_key(name, proto);
    ask_key(Database::Services, Request::ServiceByName, &key, wire::SERVICE_HEADER, |h, c| reply::service(h, c, buf))
}

/// `getservbyport_r`; `port` is in network byte order, as the C function takes it.
pub fn service_by_port(port: i32, proto: Option<&[u8]>, buf: &mut [u8]) -> Res<ServiceLayout> {
    if !Database::Services.enabled() {
        return Res::Fallback;
    }
    // (glibc formats the int as an unsigned long: a negative port becomes a 20-digit number)
    let mut digits = Key::new();
    digits.push_decimal(i64::from(port) as u64);
    let key = service_key(digits.as_bytes(), proto);
    ask_key(Database::Services, Request::ServiceByPort, &key, wire::SERVICE_HEADER, |h, c| reply::service(h, c, buf))
}

/// Memory for a reply of a size known only from its header (the caller's allocation).
pub trait Sink {
    /// Make room for `bytes` bytes; false when memory ran out.
    fn reserve(&mut self, bytes: usize) -> bool;
    /// The memory made by `reserve` (at least that long).
    fn bytes(&mut self) -> &mut [u8];
}

/// How `fill` ended.
#[derive(Debug, PartialEq, Eq)]
enum Fill {
    /// All the bytes are in the sink.
    Done,
    /// The sink could not get the memory.
    NoMemory,
    /// The daemon sent fewer bytes than its header said.
    Short,
}

/// Read `len` bytes from `conn` into the sink, which grows with what arrives (at most doubling, in steps of 64 KiB or more).
/// glibc mallocs the whole length and never touches what the daemon does not send; a sink that is zero-filled up front would
/// commit gigabytes for a header that claims them (an `int` sum of counts can reach 2 GiB), so the length is not reserved at once.
/// A length no allocation could ever have (above `isize::MAX`, a wrapped negative sum) is `NoMemory` at once, as malloc fails.
fn fill(conn: &mut impl conn::Source, sink: &mut impl Sink, len: usize) -> Fill {
    const STEP: usize = 64 * 1024;
    if len > isize::MAX as usize {
        return Fill::NoMemory;
    }
    let mut done = 0;
    while done < len {
        let step = (len - done).min(STEP);
        if !sink.reserve(len.min((done * 2).max(done + step))) {
            return Fill::NoMemory;
        }
        if conn.read_all(&mut sink.bytes()[done..done + step]) != step {
            return Fill::Short;
        }
        done += step;
    }
    Fill::Done
}

/// What `addr_info` came to.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrInfo {
    /// Ask the NSS sources instead (the daemon is disabled).
    Fallback,
    /// Final "no such name" (`EAI_NONAME`); the `h_errno` the daemon sent.
    NotFound(i32),
    /// The data is in the sink, laid out as [`AddrInfoData::split`] reads it.
    Found { naddrs: usize, addrslen: usize, canonlen: usize },
    /// The sink could not get the memory (`EAI_MEMORY`).
    NoMemory,
    /// The data stopped short or does not add up (`EAI_SYSTEM`): glibc does not fall back here.
    Failed,
}

/// The addresses of a host name for `getaddrinfo` (GETAI).
pub fn addr_info(name: &[u8], sink: &mut impl Sink) -> AddrInfo {
    if !Database::Hosts.enabled() {
        return AddrInfo::Fallback;
    }
    if localdomain_set() {
        Database::Hosts.disable();
        return AddrInfo::Fallback;
    }
    let mut key = Key::new();
    key.push(name).push(&[0]);
    if key.overflow {
        Database::Hosts.disable();
        return AddrInfo::Fallback;
    }
    let mut header = [0u8; wire::ADDRINFO_HEADER];
    let Some(mut conn) = Conn::open(Request::AddrInfo, key.as_bytes(), &mut header) else {
        Database::Hosts.disable();
        return AddrInfo::Fallback;
    };
    match wire::found(&header) {
        1 => {}
        -1 => {
            Database::Hosts.disable();
            return AddrInfo::Fallback;
        }
        _ => return AddrInfo::NotFound(wire::field(&header, 5)),
    }
    let (Some(naddrs), Some(addrslen), Some(canonlen)) = (wire::size(&header, 2), wire::size(&header, 3), wire::size(&header, 4)) else {
        return AddrInfo::Failed;
    };
    // glibc adds the three 32-bit counts as `int` (wrapping) and widens the sum to size_t, so counts that add up past
    // 2 GiB give a smaller (or, negative, a huge) length than their real sum: the same here, for the same answers.
    let datalen = (naddrs as i32).wrapping_add(addrslen as i32).wrapping_add(canonlen as i32) as isize as usize;
    match fill(&mut conn, sink, datalen) {
        Fill::Done => {}
        Fill::NoMemory => return AddrInfo::NoMemory,
        Fill::Short => return AddrInfo::Failed,
    }
    if AddrInfoData::split(&sink.bytes()[..datalen], naddrs, addrslen, canonlen).is_none() {
        return AddrInfo::Failed;
    }
    AddrInfo::Found { naddrs, addrslen, canonlen }
}

/// A list of group ids that can grow (glibc's `groups` array and `size` of `internal_getgrouplist`).
pub trait GidList {
    /// Make room for at least `entries` ids, keeping the ones stored; false when memory ran out.
    fn ensure(&mut self, entries: usize) -> bool;
    /// All the room there is.
    fn gids(&mut self) -> &mut [u32];
}

/// `__nscd_getgrouplist` with the caller's checks: the groups of `user` plus `group` (added last when not in the list),
/// stored from index 0 of `list`; the count, or None to use the NSS sources. A failure disables the daemon for a while.
pub fn init_groups(user: &[u8], group: u32, list: &mut impl GidList) -> Option<usize> {
    if !Database::Group.enabled() {
        return None;
    }
    let found = fetch_groups(user, list);
    let Some(count) = found else {
        Database::Group.disable();
        return None;
    };
    let gids = list.gids();
    if !gids[..count].contains(&group) {
        gids[count] = group;
        return Some(count + 1);
    }
    Some(count)
}

/// The ids the daemon has for `user`, in `list`; None on any failure (the room for the id added later is made here).
fn fetch_groups(user: &[u8], list: &mut impl GidList) -> Option<usize> {
    let mut key = Key::new();
    key.push(user).push(&[0]);
    if key.overflow {
        return None;
    }
    let mut header = [0u8; wire::INITGROUPS_HEADER];
    let mut conn = Conn::open(Request::InitGroups, key.as_bytes(), &mut header)?;
    match wire::found(&header) {
        1 => {}
        -1 => return None,
        _ => return list.ensure(1).then_some(0),
    }
    let count = wire::size(&header, 2)?;
    if !list.ensure(count.checked_add(1)?) {
        return None;
    }
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < count {
        let n = (count - done).min(chunk.len() / 4);
        if conn.read_all(&mut chunk[..4 * n]) != 4 * n {
            return None;
        }
        let (words, _) = chunk.as_chunks::<4>();
        for (slot, word) in list.gids()[done..done + n].iter_mut().zip(words) {
            *slot = u32::from_le_bytes(*word);
        }
        done += n;
    }
    Some(count)
}

/// What `netgroup` came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Netgroup {
    /// Ask the NSS sources instead.
    Fallback,
    /// Final "no such netgroup" (`setnetgrent` returns 0, no NSS lookup).
    NotFound,
    /// The entries, `len` bytes in the sink: for each triple three NUL-terminated strings (host, user, domain), an empty
    /// string meaning "any". Read them with [`reply::netgroup_entry`].
    Found { len: usize },
}

/// `__nscd_setnetgrent`: the flattened entries of netgroup `group`.
pub fn netgroup(group: &[u8], sink: &mut impl Sink) -> Netgroup {
    if !Database::Netgroup.enabled() {
        return Netgroup::Fallback;
    }
    let mut key = Key::new();
    key.push(group).push(&[0]);
    if key.overflow {
        Database::Netgroup.disable();
        return Netgroup::Fallback;
    }
    let mut header = [0u8; wire::NETGROUP_HEADER];
    let Some(mut conn) = Conn::open(Request::NetgroupEntries, key.as_bytes(), &mut header) else {
        Database::Netgroup.disable();
        return Netgroup::Fallback;
    };
    match wire::found(&header) {
        1 => {}
        -1 => {
            Database::Netgroup.disable();
            return Netgroup::Fallback;
        }
        _ => return Netgroup::NotFound,
    }
    let Some(len) = wire::size(&header, 3) else { return Netgroup::Fallback };
    if fill(&mut conn, sink, len) != Fill::Done {
        return Netgroup::Fallback;
    }
    Netgroup::Found { len }
}

/// What `in_netgroup` came to.
#[derive(Debug, PartialEq, Eq)]
pub enum InNetgroup {
    /// Ask the NSS sources instead.
    Fallback,
    /// The daemon does not know the netgroup (0 and `errno` cleared).
    NotFound,
    /// The daemon's verdict (1 if the triple is in the group); `errno` is left alone.
    Result(i32),
}

/// The key of an INNETGR request: the netgroup and a NUL, then for host, user and domain a 0 byte (any) or a 1 byte, the
/// string and a NUL.
fn in_netgroup_key(netgroup: &[u8], host: Option<&[u8]>, user: Option<&[u8]>, domain: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.push(netgroup).push(&[0]);
    for part in [host, user, domain] {
        match part {
            Some(s) => key.push(&[1]).push(s).push(&[0]),
            None => key.push(&[0]),
        };
    }
    key
}

/// `__nscd_innetgr`; `None` for host, user or domain means any (sent as a flag byte 0, else 1 and the string).
pub fn in_netgroup(netgroup: &[u8], host: Option<&[u8]>, user: Option<&[u8]>, domain: Option<&[u8]>) -> InNetgroup {
    if !Database::Netgroup.enabled() {
        return InNetgroup::Fallback;
    }
    let key = in_netgroup_key(netgroup, host, user, domain);
    if key.overflow {
        Database::Netgroup.disable();
        return InNetgroup::Fallback;
    }
    let mut header = [0u8; wire::INNETGROUP_HEADER];
    let Some(_conn) = Conn::open(Request::InNetgroup, key.as_bytes(), &mut header) else {
        Database::Netgroup.disable();
        return InNetgroup::Fallback;
    };
    match wire::found(&header) {
        // (a negative verdict is not an answer: glibc's caller goes on to the sources)
        1 => match wire::field(&header, 2) {
            r if r >= 0 => InNetgroup::Result(r),
            _ => InNetgroup::Fallback,
        },
        -1 => {
            Database::Netgroup.disable();
            InNetgroup::Fallback
        }
        _ => InNetgroup::NotFound,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod captured;
