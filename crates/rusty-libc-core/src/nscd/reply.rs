//! Reading the daemon's replies into the caller's buffer, in safe code on byte slices.
//!
//! Each parser takes the fixed-size reply header already read (`wire`), a [`Source`] for the data that follows, and the
//! caller's result buffer. It lays the strings and pointer vectors out in the buffer exactly as glibc 2.43 does
//! (nscd/nscd_getpw_r.c, nscd_getgr_r.c, nscd_gethst_r.c, nscd_getserv_r.c: alignment padding from the buffer's address,
//! the same size checks, so the same `ERANGE` thresholds) and returns the offsets; the caller turns offsets into pointers.
//! Pointer words stored in the buffer are the buffer's own address plus an offset.
//!
//! Differences from glibc, on replies a real nscd never sends: a negative count or length, or a string that is not
//! NUL-terminated (glibc's socket path checks neither and would hand out an unterminated string), makes the reply
//! [`Reply::Unusable`]; the caller then uses the NSS sources.
use super::conn::Source;
use super::wire;

/// What a reply parser found.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply<T> {
    /// The record, laid out in the buffer.
    Found(T),
    /// The daemon says there is no such record; `error` is the `h_errno` it sent (hosts only, else 0).
    NotFound { error: i32 },
    /// `found == -1`: the daemon does not cache this database. The caller stops asking for a while.
    Disabled,
    /// The record does not fit the buffer.
    Erange,
    /// passwd and group: the record was announced but its data stopped short (glibc returns `ENOENT`).
    Truncated,
    /// Short or malformed reply: use the NSS sources (the not-asking-for-a-while flag stays as it is).
    Unusable,
}

/// Round `addr` up to the pointer alignment: the padding glibc computes as `(alignof - p) & (alignof - 1)`.
fn pad(addr: usize) -> usize {
    8usize.wrapping_sub(addr) & 7
}

/// Store the pointer value `addr` at `off`.
fn put_pointer(buf: &mut [u8], off: usize, addr: usize) {
    buf[off..off + 8].copy_from_slice(&addr.to_ne_bytes());
}

/// The 32-bit length stored at byte `at`.
fn length_at(buf: &[u8], at: usize) -> usize {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize
}

/// Sum of the `count` lengths stored from byte `at`.
fn total_length(buf: &[u8], at: usize, count: usize) -> usize {
    (0..count).map(|i| length_at(buf, at + 4 * i)).sum()
}

/// Is the string `buf[off..off + len]` non-empty and NUL-terminated?
fn terminated(buf: &[u8], off: usize, len: usize) -> bool {
    len > 0 && buf[off + len - 1] == 0
}

/// Replace the `count` 32-bit string lengths at `vec` by pointers to the strings (which follow each other from `data`,
/// `total` bytes in all) and a NULL after them. Works backwards so that a pointer never overwrites a length not yet used.
/// None when a string is empty or not NUL-terminated.
fn lengths_to_pointers(buf: &mut [u8], vec: usize, count: usize, data: usize, total: usize) -> Option<()> {
    let base = buf.as_ptr() as usize;
    put_pointer(buf, vec + 8 * count, 0);
    let mut from_end = 0;
    for i in (0..count).rev() {
        let len = length_at(buf, vec + 4 * i);
        from_end += len;
        let start = data + (total - from_end);
        if !terminated(buf, start, len) {
            return None;
        }
        put_pointer(buf, vec + 8 * i, base + start);
    }
    Some(())
}

/// Where `getpwnam_r`'s strings are in the buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct PasswdLayout {
    pub uid: u32,
    pub gid: u32,
    pub name: usize,
    pub passwd: usize,
    pub gecos: usize,
    pub dir: usize,
    pub shell: usize,
}

/// A passwd reply: the five strings follow the header one after the other.
pub fn passwd(header: &[u8], source: &mut impl Source, buf: &mut [u8]) -> Reply<PasswdLayout> {
    match wire::found(header) {
        -1 => return Reply::Disabled,
        1 => {}
        _ => return Reply::NotFound { error: 0 },
    }
    let (Some(name_len), Some(passwd_len), Some(gecos_len), Some(dir_len), Some(shell_len)) =
        (wire::size(header, 2), wire::size(header, 3), wire::size(header, 6), wire::size(header, 7), wire::size(header, 8))
    else {
        return Reply::Unusable;
    };
    let lens = [name_len, passwd_len, gecos_len, dir_len, shell_len];
    let total: usize = lens.iter().sum();
    if buf.len() < total {
        return Reply::Erange;
    }
    if source.read_all(&mut buf[..total]) != total {
        return Reply::Truncated;
    }
    let mut at = 0;
    let mut offs = [0usize; 5];
    for (off, len) in offs.iter_mut().zip(lens) {
        if !terminated(buf, at, len) {
            return Reply::Unusable;
        }
        *off = at;
        at += len;
    }
    let [name, passwd, gecos, dir, shell] = offs;
    Reply::Found(PasswdLayout { uid: wire::field(header, 4) as u32, gid: wire::field(header, 5) as u32, name, passwd, gecos, dir, shell })
}

/// Where `getgrnam_r`'s pieces are in the buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct GroupLayout {
    pub gid: u32,
    pub name: usize,
    pub passwd: usize,
    /// The NULL-terminated vector of member pointers.
    pub members: usize,
}

/// A group reply: member lengths, name, password, then the member names.
pub fn group(header: &[u8], source: &mut impl Source, buf: &mut [u8]) -> Reply<GroupLayout> {
    match wire::found(header) {
        -1 => return Reply::Disabled,
        1 => {}
        _ => return Reply::NotFound { error: 0 },
    }
    let (Some(name_len), Some(passwd_len), Some(count)) = (wire::size(header, 2), wire::size(header, 3), wire::size(header, 5)) else {
        return Reply::Unusable;
    };
    let vec = pad(buf.as_ptr() as usize);
    let name = vec + (1 + count) * 8;
    let passwd = name + name_len;
    let first_member = passwd + passwd_len;
    if buf.len() < first_member {
        return Reply::Erange;
    }
    let room_for_members = buf.len() - first_member;
    if source.read_all(&mut buf[vec..vec + 4 * count]) != 4 * count || source.read_all(&mut buf[name..first_member]) != first_member - name {
        return Reply::Unusable;
    }
    let members_len = total_length(buf, vec, count);
    if members_len > room_for_members {
        return Reply::Erange;
    }
    if source.read_all(&mut buf[first_member..first_member + members_len]) != members_len {
        return Reply::Truncated;
    }
    if !terminated(buf, name, name_len) || !terminated(buf, passwd, passwd_len) || lengths_to_pointers(buf, vec, count, first_member, members_len).is_none() {
        return Reply::Unusable;
    }
    Reply::Found(GroupLayout { gid: wire::field(header, 4) as u32, name, passwd, members: vec })
}

/// Where `gethostbyname_r`'s pieces are in the buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct HostLayout {
    pub addrtype: i32,
    pub length: i32,
    pub name: usize,
    pub aliases: usize,
    pub addr_list: usize,
}

/// A hosts reply for an IPv4 (`v6 == false`) or IPv6 request: name, alias lengths, addresses, then the alias names.
pub fn host(header: &[u8], v6: bool, source: &mut impl Source, buf: &mut [u8]) -> Reply<HostLayout> {
    match wire::found(header) {
        -1 => return Reply::Disabled,
        1 => {}
        _ => return Reply::NotFound { error: wire::field(header, 7) },
    }
    let (Some(name_len), Some(alias_count), Some(addr_count)) = (wire::size(header, 2), wire::size(header, 3), wire::size(header, 6)) else {
        return Reply::Unusable;
    };
    let reply_addr_len = wire::field(header, 5);
    let addr_len = if v6 { 16 } else { 4 };
    let base = buf.as_ptr() as usize;
    let first = pad(base);
    let after_name = pad(base + first + name_len);
    // glibc compares `type == AF_INET` where `type` is the request type (4 to 7, never 2): every address counts 16 bytes here
    let need = first + name_len + after_name + (alias_count + addr_count + 2) * 8 + addr_count * 16;
    if buf.len() < need {
        return Reply::Erange;
    }
    let aliases = first;
    let addr_list = aliases + (alias_count + 1) * 8;
    let name = addr_list + (addr_count + 1) * 8;
    let addrs = name + name_len + after_name;
    let alias_data = addrs + addr_count * addr_len;
    let mut complete = source.read_all(&mut buf[name..name + name_len]) == name_len;
    complete = complete && source.read_all(&mut buf[aliases..aliases + 4 * alias_count]) == 4 * alias_count;
    if complete && v6 && reply_addr_len == 4 {
        // (IPv4 addresses sent ahead of the IPv6 ones in the answer to an IPv6 request: read and dropped)
        let mut left = addr_count * 4;
        let mut skipped = [0u8; 64];
        while complete && left > 0 {
            let n = left.min(skipped.len());
            complete = source.read_all(&mut skipped[..n]) == n;
            left -= n;
        }
    }
    complete = complete && source.read_all(&mut buf[addrs..alias_data]) == alias_data - addrs;
    if !complete {
        return Reply::Unusable;
    }
    let aliases_len = total_length(buf, aliases, alias_count);
    if alias_data + aliases_len > buf.len() {
        return Reply::Erange;
    }
    if source.read_all(&mut buf[alias_data..alias_data + aliases_len]) != aliases_len {
        return Reply::Unusable;
    }
    for i in 0..addr_count {
        put_pointer(buf, addr_list + 8 * i, base + addrs + i * addr_len);
    }
    put_pointer(buf, addr_list + 8 * addr_count, 0);
    if !terminated(buf, name, name_len) || lengths_to_pointers(buf, aliases, alias_count, alias_data, aliases_len).is_none() {
        return Reply::Unusable;
    }
    Reply::Found(HostLayout { addrtype: if v6 { 10 } else { 2 }, length: addr_len as i32, name, aliases, addr_list })
}

/// Where `getservbyname_r`'s pieces are in the buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceLayout {
    /// The port, as the daemon sent it (network byte order).
    pub port: i32,
    pub name: usize,
    pub proto: usize,
    pub aliases: usize,
}

/// A services reply: name and protocol, alias lengths, then the alias names.
pub fn service(header: &[u8], source: &mut impl Source, buf: &mut [u8]) -> Reply<ServiceLayout> {
    match wire::found(header) {
        -1 => return Reply::Disabled,
        1 => {}
        _ => return Reply::NotFound { error: 0 },
    }
    let (Some(name_len), Some(proto_len), Some(alias_count)) = (wire::size(header, 2), wire::size(header, 3), wire::size(header, 4)) else {
        return Reply::Unusable;
    };
    let base = buf.as_ptr() as usize;
    let aliases = pad(base);
    let after_proto = pad(base + aliases + name_len + proto_len);
    if buf.len() < aliases + name_len + proto_len + after_proto + (alias_count + 1) * 8 {
        return Reply::Erange;
    }
    let name = aliases + (alias_count + 1) * 8;
    let proto = name + name_len;
    let alias_data = proto + proto_len + after_proto;
    if source.read_all(&mut buf[name..proto + proto_len]) != name_len + proto_len || source.read_all(&mut buf[aliases..aliases + 4 * alias_count]) != 4 * alias_count {
        return Reply::Unusable;
    }
    let aliases_len = total_length(buf, aliases, alias_count);
    if alias_data + aliases_len > buf.len() {
        return Reply::Erange;
    }
    if source.read_all(&mut buf[alias_data..alias_data + aliases_len]) != aliases_len {
        return Reply::Unusable;
    }
    if !terminated(buf, name, name_len) || !terminated(buf, proto, proto_len) || lengths_to_pointers(buf, aliases, alias_count, alias_data, aliases_len).is_none() {
        return Reply::Unusable;
    }
    Reply::Found(ServiceLayout { port: wire::field(header, 5), name, proto, aliases })
}

/// The pieces of a GETAI reply's data: `addrs` (4 or 16 bytes each), `family` (one byte per address), the canonical name.
#[derive(Debug, PartialEq, Eq)]
pub struct AddrInfoData<'a> {
    pub family: &'a [u8],
    pub addrs: &'a [u8],
    /// The canonical name without its NUL (None when the reply carries none).
    pub canon: Option<&'a [u8]>,
}

impl<'a> AddrInfoData<'a> {
    /// Split the data that follows a GETAI header (`addrslen` bytes of addresses, `naddrs` family bytes, `canonlen` bytes of
    /// name). None when the sizes do not add up or the name is not NUL-terminated.
    pub fn split(data: &'a [u8], naddrs: usize, addrslen: usize, canonlen: usize) -> Option<AddrInfoData<'a>> {
        if data.len() != naddrs.checked_add(addrslen)?.checked_add(canonlen)? {
            return None;
        }
        let (addrs, rest) = data.split_at(addrslen);
        let (family, canon) = rest.split_at(naddrs);
        let used: usize = family.iter().map(|&f| Self::address_size(f)).sum();
        if used > addrslen {
            return None;
        }
        let canon = match canon.split_last() {
            None => None,
            Some((0, name)) => Some(name),
            Some(_) => return None,
        };
        Some(AddrInfoData { family, addrs, canon })
    }

    /// Bytes an address of `family` takes: 4 for `AF_INET`, else 16.
    pub fn address_size(family: u8) -> usize {
        if family == 2 { 4 } else { 16 }
    }

    /// Each address with its family.
    pub fn addresses(&self) -> impl Iterator<Item = (u8, &'a [u8])> + 'a {
        let (family, mut rest): (&'a [u8], &'a [u8]) = (self.family, self.addrs);
        family.iter().map(move |&f| {
            let (a, r) = rest.split_at(Self::address_size(f));
            rest = r;
            (f, a)
        })
    }
}

/// The next entry of a netgroup reply: `(host, user, domain)` as byte ranges of `data` (None for an empty string, glibc's
/// NULL), moving `cursor` past it. None at the end of the data, or when an entry is cut short.
pub fn netgroup_entry(data: &[u8], cursor: &mut usize) -> Option<[Option<core::ops::Range<usize>>; 3]> {
    if *cursor >= data.len() {
        return None;
    }
    let mut at = *cursor;
    let mut out = [None, None, None];
    for slot in &mut out {
        let len = data.get(at..)?.iter().position(|&b| b == 0)?;
        *slot = (len > 0).then(|| at..at + len);
        at += len + 1;
    }
    *cursor = at;
    Some(out)
}
