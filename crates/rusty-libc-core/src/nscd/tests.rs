//! Request encoding and reply parsing against byte vectors. The vectors are laid out as glibc 2.43's nscd sends them
//! (nscd/*cache.c, checked against the replies of the real daemon: see `captured` below).
use super::conn::Source;
use super::reply::{self, AddrInfoData, Reply};
use super::wire::{self, Request};
use super::{Database, Res};
use crate::nssent;

/// A reply that is a byte vector.
struct Mem<'a>(&'a [u8]);

impl Source for Mem<'_> {
    fn read_all(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.0.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        n
    }
}

fn words(w: &[i32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// A buffer whose first byte has address `misalign` modulo 8.
struct Aligned {
    store: Vec<u8>,
    start: usize,
}

impl Aligned {
    fn new(len: usize, misalign: usize) -> Aligned {
        let store = vec![0u8; len + 16];
        let base = store.as_ptr() as usize;
        let start = (misalign + 8 - base % 8) % 8;
        Aligned { store, start }
    }
    fn buf(&mut self, len: usize) -> &mut [u8] {
        &mut self.store[self.start..self.start + len]
    }
}

/// The word stored at `off` of `buf` as an offset from the buffer's start (0 stays 0).
fn pointer_at(buf: &[u8], off: usize) -> usize {
    let v = usize::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
    if v == 0 { 0 } else { v - buf.as_ptr() as usize }
}

fn cstr_at(buf: &[u8], off: usize) -> &str {
    let end = buf[off..].iter().position(|&b| b == 0).unwrap();
    core::str::from_utf8(&buf[off..off + end]).unwrap()
}

#[test]
fn request_bytes() {
    let mut out = [0u8; 64];
    // GETPWBYNAME "root": version 2, type 0, key length 5 (with the NUL)
    let n = wire::encode_request(Request::PasswdByName, b"root\0", &mut out).unwrap();
    assert_eq!(&out[..n], &[2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, b'r', b'o', b'o', b't', 0]);
    // GETAI is type 14, INITGROUPS 15, GETSERVBYNAME 16, GETSERVBYPORT 17, GETNETGRENT 19, INNETGR 20
    for (req, t) in [(Request::AddrInfo, 14), (Request::InitGroups, 15), (Request::ServiceByName, 16), (Request::ServiceByPort, 17), (Request::NetgroupEntries, 19), (Request::InNetgroup, 20), (Request::HostByAddrV6, 7), (Request::GroupByGid, 3)] {
        let n = wire::encode_request(req, b"k", &mut out).unwrap();
        assert_eq!(&out[..n], &[2, 0, 0, 0, t, 0, 0, 0, 1, 0, 0, 0, b'k']);
    }
    // a key that does not fit
    assert_eq!(wire::encode_request(Request::PasswdByUid, &[0; 60], &mut out), None);
}

#[test]
fn passwd_found_and_erange_threshold() {
    let strings = [cstr("alice"), cstr("x"), cstr("Alice A"), cstr("/home/alice"), cstr("/bin/sh")];
    let total: usize = strings.iter().map(Vec::len).sum();
    let mut reply = words(&[2, 1, 6, 2, 0, 0, 8, 12, 8]);
    reply[16..20].copy_from_slice(&1000u32.to_le_bytes());
    reply[20..24].copy_from_slice(&1001u32.to_le_bytes());
    let data = strings.concat();
    let mut a = Aligned::new(200, 3);
    let buf = a.buf(total);
    let Reply::Found(l) = reply::passwd(&reply[..36], &mut Mem(&data), buf) else { panic!() };
    assert_eq!((l.uid, l.gid), (1000, 1001));
    assert_eq!(cstr_at(buf, l.name), "alice");
    assert_eq!(cstr_at(buf, l.passwd), "x");
    assert_eq!(cstr_at(buf, l.gecos), "Alice A");
    assert_eq!(cstr_at(buf, l.dir), "/home/alice");
    assert_eq!(cstr_at(buf, l.shell), "/bin/sh");
    // one byte less than the strings need: ERANGE, before any data is read
    let mut src = Mem(&data);
    assert_eq!(reply::passwd(&reply[..36], &mut src, a.buf(total - 1)), Reply::Erange);
    assert_eq!(src.0.len(), data.len());
    // the data stops short: the record was announced, glibc returns ENOENT
    assert_eq!(reply::passwd(&reply[..36], &mut Mem(&data[..data.len() - 1]), a.buf(total)), Reply::Truncated);
}

#[test]
fn passwd_other_replies() {
    let notfound = {
        let mut r = words(&[2, 0, 0, 0, -1, -1, 0, 0, 0]);
        r.truncate(36);
        r
    };
    let mut buf = [0u8; 64];
    assert_eq!(reply::passwd(&notfound, &mut Mem(&[]), &mut buf), Reply::NotFound { error: 0 });
    let disabled = words(&[2, -1, 0, 0, -1, -1, 0, 0, 0]);
    assert_eq!(reply::passwd(&disabled, &mut Mem(&[]), &mut buf), Reply::Disabled);
    // a negative length, and a string that is not NUL-terminated
    let negative = words(&[2, 1, -1, 2, 0, 0, 2, 2, 2]);
    assert_eq!(reply::passwd(&negative, &mut Mem(&[0; 20]), &mut buf), Reply::Unusable);
    let ok_lens = words(&[2, 1, 2, 2, 0, 0, 2, 2, 2]);
    assert_eq!(reply::passwd(&ok_lens, &mut Mem(b"ab\0cd\0ef\0gh\0ij\0"), &mut buf), Reply::Unusable);
    // found = 7 is neither 1 nor -1: not found
    let odd = words(&[2, 7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(reply::passwd(&odd, &mut Mem(&[]), &mut buf), Reply::NotFound { error: 0 });
}

fn group_reply(name: &str, passwd: &str, gid: u32, members: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let mut header = words(&[2, 1, name.len() as i32 + 1, passwd.len() as i32 + 1, 0, members.len() as i32]);
    header[16..20].copy_from_slice(&gid.to_le_bytes());
    let mut data = Vec::new();
    for m in members {
        data.extend((m.len() as u32 + 1).to_le_bytes());
    }
    data.extend(cstr(name));
    data.extend(cstr(passwd));
    for m in members {
        data.extend(cstr(m));
    }
    (header, data)
}

#[test]
fn group_members_pointers_in_every_alignment() {
    let (header, data) = group_reply("staff", "x", 50, &["ann", "bob", "carol"]);
    for misalign in 0..8 {
        let mut a = Aligned::new(300, misalign);
        let pad = (8 - misalign) % 8;
        // the exact size glibc needs: padding, 4 pointers, the strings
        let need = pad + 4 * 8 + 6 + 2 + 4 + 4 + 6;
        let Reply::Found(l) = reply::group(&header, &mut Mem(&data), a.buf(need)) else { panic!("misalign {misalign}") };
        let buf = a.buf(need);
        assert_eq!(l.members, pad);
        assert_eq!(l.gid, 50);
        assert_eq!(cstr_at(buf, l.name), "staff");
        assert_eq!(cstr_at(buf, l.passwd), "x");
        let names: Vec<&str> = (0..3).map(|i| cstr_at(buf, pointer_at(buf, l.members + 8 * i))).collect();
        assert_eq!(names, ["ann", "bob", "carol"]);
        assert_eq!(pointer_at(buf, l.members + 24), 0);
        assert_eq!(reply::group(&header, &mut Mem(&data), a.buf(need - 1)), Reply::Erange, "misalign {misalign}");
    }
}

#[test]
fn group_without_members_and_short_data() {
    let (header, data) = group_reply("empty", "", 9, &[]);
    let mut a = Aligned::new(100, 0);
    let Reply::Found(l) = reply::group(&header, &mut Mem(&data), a.buf(8 + 6 + 1)) else { panic!() };
    assert_eq!(pointer_at(a.buf(15), l.members), 0);
    // the name and password cut short: use the NSS sources; the members cut short: ENOENT
    let (header, data) = group_reply("staff", "x", 50, &["ann"]);
    assert_eq!(reply::group(&header, &mut Mem(&data[..8]), a.buf(100)), Reply::Unusable);
    assert_eq!(reply::group(&header, &mut Mem(&data[..data.len() - 2]), a.buf(100)), Reply::Truncated);
}

fn host_reply(v6: bool, name: &str, aliases: &[&str], addrs: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
    let header = words(&[2, 1, name.len() as i32 + 1, aliases.len() as i32, if v6 { 10 } else { 2 }, if v6 { 16 } else { 4 }, addrs.len() as i32, 0]);
    let mut data = cstr(name);
    for a in aliases {
        data.extend((a.len() as u32 + 1).to_le_bytes());
    }
    for a in addrs {
        data.extend(*a);
    }
    for a in aliases {
        data.extend(cstr(a));
    }
    (header, data)
}

#[test]
fn host_v4_layout_and_the_sixteen_byte_threshold() {
    let (header, data) = host_reply(false, "h.example", &["a.example", "b"], &[&[10, 0, 0, 1], &[10, 0, 0, 2]]);
    let mut a = Aligned::new(400, 0);
    // glibc compares the buffer with `align + name + align + (aliases + addrs + 2) pointers + addrs * 16`: the threshold counts
    // 16 bytes per address although IPv4 addresses take 4
    let name_len = 10;
    let pad2 = (8 - name_len % 8) % 8;
    let need = name_len + pad2 + (2 + 2 + 2) * 8 + 2 * 16;
    assert_eq!(reply::host(&header, false, &mut Mem(&data), a.buf(need - 1)), Reply::Erange);
    let Reply::Found(l) = reply::host(&header, false, &mut Mem(&data), a.buf(need)) else { panic!() };
    let buf = a.buf(need);
    assert_eq!((l.addrtype, l.length), (2, 4));
    assert_eq!(cstr_at(buf, l.name), "h.example");
    let al: Vec<&str> = (0..2).map(|i| cstr_at(buf, pointer_at(buf, l.aliases + 8 * i))).collect();
    assert_eq!(al, ["a.example", "b"]);
    assert_eq!(pointer_at(buf, l.aliases + 16), 0);
    let first = pointer_at(buf, l.addr_list);
    assert_eq!(&buf[first..first + 4], &[10, 0, 0, 1]);
    let second = pointer_at(buf, l.addr_list + 8);
    assert_eq!(&buf[second..second + 4], &[10, 0, 0, 2]);
    assert_eq!(second, first + 4);
    assert_eq!(pointer_at(buf, l.addr_list + 16), 0);
}

#[test]
fn host_v6_and_notfound() {
    let a6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let (header, data) = host_reply(true, "v6", &[], &[&a6]);
    let mut a = Aligned::new(200, 5);
    let Reply::Found(l) = reply::host(&header, true, &mut Mem(&data), a.buf(200)) else { panic!() };
    let buf = a.buf(200);
    assert_eq!((l.addrtype, l.length), (10, 16));
    let p = pointer_at(buf, l.addr_list);
    assert_eq!(&buf[p..p + 16], &a6);
    // an IPv6 request answered with 4-byte addresses first: those are skipped
    let mut header4 = header.clone();
    header4[20..24].copy_from_slice(&4i32.to_le_bytes());
    let mut data4 = cstr("v6");
    data4.extend([1, 2, 3, 4]);
    data4.extend(a6);
    let Reply::Found(l) = reply::host(&header4, true, &mut Mem(&data4), a.buf(200)) else { panic!() };
    let p = pointer_at(a.buf(200), l.addr_list);
    assert_eq!(&a.buf(200)[p..p + 16], &a6);
    // not found carries the h_errno (1: HOST_NOT_FOUND, 2: TRY_AGAIN)
    let nf = words(&[2, 0, 0, 0, -1, -1, 0, 1]);
    assert_eq!(reply::host(&nf, false, &mut Mem(&[]), a.buf(200)), Reply::NotFound { error: 1 });
    let tryagain = words(&[2, 0, 0, 0, -1, -1, 0, 2]);
    assert_eq!(reply::host(&tryagain, false, &mut Mem(&[]), a.buf(200)), Reply::NotFound { error: 2 });
}

#[test]
fn service_layout_and_threshold() {
    // name "http", protocol "tcp", aliases "www", port 80 in network byte order
    let mut header = words(&[2, 1, 5, 4, 1, 0]);
    header[20..24].copy_from_slice(&[0, 80, 0, 0]);
    let mut data = cstr("http");
    data.extend(cstr("tcp"));
    data.extend(4u32.to_le_bytes());
    data.extend(cstr("www"));
    for misalign in 0..8 {
        let mut a = Aligned::new(100, misalign);
        let pad = (8 - misalign) % 8;
        let pad2 = (8 - (misalign + pad + 9) % 8) % 8;
        let need = pad + 9 + pad2 + 2 * 8;
        // only the pointers and the name and protocol are checked up front; the alias must fit as well
        let full = need + 4;
        assert_eq!(reply::service(&header, &mut Mem(&data), a.buf(full - 1)), Reply::Erange, "misalign {misalign}");
        let Reply::Found(l) = reply::service(&header, &mut Mem(&data), a.buf(full)) else { panic!("misalign {misalign}") };
        let buf = a.buf(full);
        assert_eq!(l.port, i32::from_le_bytes(header[20..24].try_into().unwrap()));
        assert_eq!(cstr_at(buf, l.name), "http");
        assert_eq!(cstr_at(buf, l.proto), "tcp");
        assert_eq!(cstr_at(buf, pointer_at(buf, l.aliases)), "www");
        assert_eq!(pointer_at(buf, l.aliases + 8), 0);
        assert_eq!(reply::service(&header, &mut Mem(&data), a.buf(need - 1)), Reply::Erange);
    }
}

#[test]
fn addrinfo_data_splits() {
    let a4 = [192, 0, 2, 1];
    let a6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut data = Vec::new();
    data.extend(a6);
    data.extend(a4);
    data.extend([10u8, 2]);
    data.extend(cstr("canon.example"));
    let d = AddrInfoData::split(&data, 2, 20, 14).unwrap();
    assert_eq!(d.canon, Some(&b"canon.example"[..]));
    let got: Vec<(u8, &[u8])> = d.addresses().collect();
    assert_eq!(got, [(10, &a6[..]), (2, &a4[..])]);
    // no canonical name
    assert_eq!(AddrInfoData::split(&data[..22], 2, 20, 0).unwrap().canon, None);
    // sizes that do not add up, a name without its NUL, addresses longer than the area
    assert!(AddrInfoData::split(&data, 2, 20, 13).is_none());
    assert!(AddrInfoData::split(&data[..data.len() - 1], 2, 20, 13).is_none());
    assert!(AddrInfoData::split(&data, 2, 19, 15).is_none());
}

#[test]
fn netgroup_entries() {
    let data = b"host1\0user1\0dom1\0\0user2\0\0host3\0\0dom3\0";
    let mut at = 0;
    let mut got = Vec::new();
    while let Some(e) = reply::netgroup_entry(data, &mut at) {
        got.push(e.map(|r| r.map(|r| core::str::from_utf8(&data[r]).unwrap().to_string())));
    }
    assert_eq!(got.len(), 3);
    assert_eq!(got[0], [Some("host1".into()), Some("user1".into()), Some("dom1".into())]);
    assert_eq!(got[1], [None, Some("user2".into()), None]);
    assert_eq!(got[2], [Some("host3".into()), None, Some("dom3".into())]);
    // an entry cut short ends the list
    let mut at = 0;
    assert!(reply::netgroup_entry(b"host\0user\0dom", &mut at).is_none());
    assert!(reply::netgroup_entry(b"", &mut 0).is_none());
}

#[test]
fn skip_flag_counts_one_hundred_calls() {
    let db = Database::Services;
    db.set_flag(0);
    assert!(db.enabled());
    db.disable();
    assert_eq!(db.flag(), 1);
    // glibc: `if (flag > 0 && ++flag > NSS_NSCD_RETRY) flag = 0; if (!flag) ask`: 99 calls skip, the 100th asks again
    for call in 1..=99 {
        assert!(!db.enabled(), "call {call}");
        assert_eq!(db.flag(), call + 1);
    }
    assert!(db.enabled());
    assert_eq!(db.flag(), 0);
    // nscd's own process disables the client with -1: never asked, never counted
    db.set_flag(-1);
    assert!(!db.enabled());
    assert_eq!(db.flag(), -1);
    db.set_flag(0);
}

#[test]
fn configured_lookup_skips_the_daemon() {
    // __nss_configure_lookup for a database turns the daemon off for it (glibc: __nss_database_custom)
    let db = Database::Netgroup;
    db.set_flag(0);
    assert!(db.enabled());
    assert!(nssent::configure(b"netgroup", b"files"));
    assert!(!db.enabled());
}

#[test]
fn results_map_to_c_codes() {
    // the three kinds of "no entry" differ in what the C function returns
    assert_ne!(Res::<()>::NotFound(0), Res::Erange);
    assert_ne!(Res::<()>::Enoent, Res::Fallback);
}

// ---- the real daemon's replies (captured.rs)

use super::captured as real;

/// A captured reply split into its header (`n` bytes) and the data after it.
fn split(reply: &[u8], n: usize) -> (&[u8], &[u8]) {
    reply.split_at(n)
}

#[test]
fn captured_passwd() {
    let mut a = Aligned::new(512, 0);
    for (reply, key) in [(real::PASSWD_BY_NAME, "nscduser"), (real::PASSWD_BY_UID, "4242")] {
        let (h, d) = split(reply, wire::PASSWD_HEADER);
        let Reply::Found(l) = reply::passwd(h, &mut Mem(d), a.buf(512)) else { panic!("{key}") };
        let buf = a.buf(512);
        assert_eq!((l.uid, l.gid), (4242, 4243));
        assert_eq!(cstr_at(buf, l.name), "nscduser");
        assert_eq!(cstr_at(buf, l.passwd), "x");
        assert_eq!(cstr_at(buf, l.gecos), "Nscd Only User");
        assert_eq!(cstr_at(buf, l.dir), "/home/nscduser");
        assert_eq!(cstr_at(buf, l.shell), "/bin/nscdsh");
    }
    // empty password, gecos and shell are one NUL byte each
    let (h, d) = split(real::PASSWD_EMPTY_FIELDS, wire::PASSWD_HEADER);
    let Reply::Found(l) = reply::passwd(h, &mut Mem(d), a.buf(512)) else { panic!() };
    let buf = a.buf(512);
    assert_eq!((cstr_at(buf, l.passwd), cstr_at(buf, l.gecos), cstr_at(buf, l.dir), cstr_at(buf, l.shell)), ("", "", "/", ""));
    let (h, d) = split(real::PASSWD_NOT_FOUND, wire::PASSWD_HEADER);
    assert_eq!(reply::passwd(h, &mut Mem(d), a.buf(512)), Reply::NotFound { error: 0 });
}

#[test]
fn captured_group() {
    let mut a = Aligned::new(512, 0);
    for reply in [real::GROUP_BY_NAME, real::GROUP_BY_GID] {
        let (h, d) = split(reply, wire::GROUP_HEADER);
        let Reply::Found(l) = reply::group(h, &mut Mem(d), a.buf(512)) else { panic!() };
        let buf = a.buf(512);
        assert_eq!((l.gid, cstr_at(buf, l.name), cstr_at(buf, l.passwd)), (4243, "nscdgroup", "x"));
        let members: Vec<&str> = (0..3).map(|i| cstr_at(buf, pointer_at(buf, l.members + 8 * i))).collect();
        assert_eq!(members, ["nscduser", "alice", "bob"]);
        assert_eq!(pointer_at(buf, l.members + 24), 0);
    }
    let (h, d) = split(real::GROUP_NO_MEMBERS, wire::GROUP_HEADER);
    let Reply::Found(l) = reply::group(h, &mut Mem(d), a.buf(512)) else { panic!() };
    assert_eq!((l.gid, pointer_at(a.buf(512), l.members)), (4244, 0));
    let (h, d) = split(real::GROUP_NOT_FOUND, wire::GROUP_HEADER);
    assert_eq!(reply::group(h, &mut Mem(d), a.buf(512)), Reply::NotFound { error: 0 });
}

#[test]
fn captured_hosts() {
    let mut a = Aligned::new(512, 0);
    for reply in [real::HOST_BY_NAME, real::HOST_BY_ADDR] {
        let (h, d) = split(reply, wire::HOST_HEADER);
        let Reply::Found(l) = reply::host(h, false, &mut Mem(d), a.buf(512)) else { panic!() };
        let buf = a.buf(512);
        assert_eq!((l.addrtype, l.length), (2, 4));
        assert_eq!(cstr_at(buf, l.name), "nscdhost.example");
        let aliases: Vec<&str> = (0..2).map(|i| cstr_at(buf, pointer_at(buf, l.aliases + 8 * i))).collect();
        assert_eq!(aliases, ["alias1.example", "alias2.example"]);
        let first = pointer_at(buf, l.addr_list);
        assert_eq!(&buf[first..first + 4], &[192, 0, 2, 10]);
    }
    let v6addr = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
    for reply in [real::HOST_BY_NAME_V6, real::HOST_BY_ADDR_V6] {
        let (h, d) = split(reply, wire::HOST_HEADER);
        let Reply::Found(l) = reply::host(h, true, &mut Mem(d), a.buf(512)) else { panic!() };
        let buf = a.buf(512);
        assert_eq!((l.addrtype, l.length), (10, 16));
        let first = pointer_at(buf, l.addr_list);
        assert_eq!(&buf[first..first + 16], &v6addr);
    }
    let (h, d) = split(real::HOST_BY_NAME_MANY, wire::HOST_HEADER);
    let Reply::Found(l) = reply::host(h, false, &mut Mem(d), a.buf(512)) else { panic!() };
    assert_eq!(cstr_at(a.buf(512), l.name), "manyaddr.example");
    // HOST_NOT_FOUND (1) comes with found = 0
    let (h, d) = split(real::HOST_NOT_FOUND, wire::HOST_HEADER);
    assert_eq!(reply::host(h, false, &mut Mem(d), a.buf(512)), Reply::NotFound { error: 1 });
    // the thresholds on a real reply: 17 bytes of name, padding to 8, (2 aliases + 1 address + 2) pointers, 16 per address
    let (h, d) = split(real::HOST_BY_NAME, wire::HOST_HEADER);
    let need = 17 + 7 + (2 + 1 + 2) * 8 + 16;
    assert_eq!(reply::host(h, false, &mut Mem(d), a.buf(need - 1)), Reply::Erange);
    assert!(matches!(reply::host(h, false, &mut Mem(d), a.buf(need + 32)), Reply::Found(_)));
}

#[test]
fn captured_addrinfo_initgroups_netgroup() {
    let (h, d) = split(real::ADDRINFO, wire::ADDRINFO_HEADER);
    assert_eq!(wire::found(h), 1);
    let (naddrs, addrslen, canonlen) = (wire::size(h, 2).unwrap(), wire::size(h, 3).unwrap(), wire::size(h, 4).unwrap());
    let info = AddrInfoData::split(d, naddrs, addrslen, canonlen).unwrap();
    assert_eq!(info.canon, Some(&b"nscdhost.example"[..]));
    assert!(info.addresses().any(|(f, a)| f == 2 && a == [192, 0, 2, 10]));
    let (h, _) = split(real::ADDRINFO_NOT_FOUND, wire::ADDRINFO_HEADER);
    assert_eq!((wire::found(h), wire::field(h, 5)), (0, 0));

    let (h, d) = split(real::INITGROUPS, wire::INITGROUPS_HEADER);
    assert_eq!((wire::found(h), wire::size(h, 2)), (1, Some(3)));
    let gids: Vec<u32> = d.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!(gids, [4243, 4246, 4247]);
    let (h, d) = split(real::INITGROUPS_NOT_FOUND, wire::INITGROUPS_HEADER);
    assert_eq!((wire::found(h), wire::size(h, 2), d.len()), (0, Some(0), 0));

    let (h, d) = split(real::NETGROUP, wire::NETGROUP_HEADER);
    assert_eq!((wire::found(h), wire::size(h, 3)), (1, Some(d.len())));
    let mut at = 0;
    let mut entries = 0;
    while reply::netgroup_entry(d, &mut at).is_some() {
        entries += 1;
    }
    // nscdng has three entries and names nscdng2 (one more): the daemon sends them flattened
    assert_eq!(entries, 4);
    assert_eq!(at, d.len());
    let (h, _) = split(real::NETGROUP_NOT_FOUND, wire::NETGROUP_HEADER);
    assert_eq!(wire::found(h), 0);

    let (h, _) = split(real::INNETGR_YES, wire::INNETGROUP_HEADER);
    assert_eq!((wire::found(h), wire::field(h, 2)), (1, 1));
    let (h, _) = split(real::INNETGR_NO, wire::INNETGROUP_HEADER);
    assert_eq!((wire::found(h), wire::field(h, 2)), (1, 0));
    // an unknown netgroup: the daemon closes the connection without a reply
    assert!(real::INNETGR_NO_GROUP.is_empty());
}

#[test]
fn captured_services() {
    let mut a = Aligned::new(512, 0);
    for reply in [real::SERVICE_BY_NAME, real::SERVICE_BY_PORT] {
        let (h, d) = split(reply, wire::SERVICE_HEADER);
        let Reply::Found(l) = reply::service(h, &mut Mem(d), a.buf(512)) else { panic!() };
        let buf = a.buf(512);
        assert_eq!(l.port, i32::from(4711u16.to_be()));
        assert_eq!((cstr_at(buf, l.name), cstr_at(buf, l.proto)), ("nscdsvc", "tcp"));
        let aliases: Vec<&str> = (0..2).map(|i| cstr_at(buf, pointer_at(buf, l.aliases + 8 * i))).collect();
        assert_eq!(aliases, ["nscdalias", "nscdalias2"]);
    }
    let (h, d) = split(real::SERVICE_NOT_FOUND, wire::SERVICE_HEADER);
    assert_eq!(reply::service(h, &mut Mem(d), a.buf(512)), Reply::NotFound { error: 0 });
}

#[test]
fn keys_as_the_glibc_client_sends_them() {
    // (the keys glibc 2.43's client sent to the test daemon, from its request log)
    assert_eq!(super::in_netgroup_key(b"nscdng", Some(b"host1"), Some(b"user1"), Some(b"dom1")).as_bytes(), b"nscdng\0\x01host1\0\x01user1\0\x01dom1\0");
    assert_eq!(super::in_netgroup_key(b"nscdng", Some(b"host1"), None, None).as_bytes(), b"nscdng\0\x01host1\0\0\0");
    assert_eq!(super::in_netgroup_key(b"nscdng", None, Some(b"user2"), None).as_bytes(), b"nscdng\0\0\x01user2\0\0");
    assert_eq!(super::in_netgroup_key(b"nosuchng", None, None, None).as_bytes(), b"nosuchng\0\0\0\0");
    assert_eq!(super::service_key(b"nscdsvc", Some(b"tcp")).as_bytes(), b"nscdsvc/tcp\0");
    assert_eq!(super::service_key(b"nscdsvc", None).as_bytes(), b"nscdsvc/\0");
    let mut port = super::Key::new();
    port.push_decimal(u64::from(4711u16.to_be()));
    assert_eq!(super::service_key(port.as_bytes(), Some(b"tcp")).as_bytes(), b"26386/tcp\0");
    assert_eq!(super::service_key(port.as_bytes(), None).as_bytes(), b"26386/\0");
    let mut uid = super::Key::new();
    uid.push_decimal(4242).push(&[0]);
    assert_eq!(uid.as_bytes(), b"4242\0");
    // a key over 1024 bytes cannot be sent
    let mut long = super::Key::new();
    long.push(&[b'x'; 1024]);
    assert!(!long.overflow);
    long.push(&[0]);
    assert!(long.overflow);
}
