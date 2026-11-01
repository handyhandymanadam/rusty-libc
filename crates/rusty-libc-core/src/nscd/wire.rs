//! The bytes of the nscd protocol (version 2): request encoding and the reply header layouts.
//!
//! Layouts from glibc 2.43 nscd/nscd-client.h (read as reference): every field is a 32-bit integer in the machine's byte
//! order (little endian here), no padding. A request is `{version, type, key_len}` followed by the key.

/// `NSCD_VERSION`.
pub const VERSION: i32 = 2;
/// `MAXKEYLEN`: the longest key the daemon accepts.
pub const MAXKEYLEN: usize = 1024;
/// Size of the request header.
pub const REQUEST_HEADER: usize = 12;

/// The request types the client sends (glibc's `request_type`, numbered as in the header). The shared-memory requests
/// (`GETFDPW`, `GETFDGR`, `GETFDHST`, `GETFDSERV`, `GETFDNETGR`) are never sent here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Request {
    PasswdByName = 0,
    PasswdByUid = 1,
    GroupByName = 2,
    GroupByGid = 3,
    HostByName = 4,
    HostByNameV6 = 5,
    HostByAddr = 6,
    HostByAddrV6 = 7,
    AddrInfo = 14,
    InitGroups = 15,
    ServiceByName = 16,
    ServiceByPort = 17,
    NetgroupEntries = 19,
    InNetgroup = 20,
}

/// Write the request for `key` into `out`; returns its length, or None when `out` is too small.
pub fn encode_request(req: Request, key: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = REQUEST_HEADER + key.len();
    let out = out.get_mut(..total)?;
    out[0..4].copy_from_slice(&VERSION.to_le_bytes());
    out[4..8].copy_from_slice(&(req as i32).to_le_bytes());
    out[8..12].copy_from_slice(&(key.len() as i32).to_le_bytes());
    out[REQUEST_HEADER..].copy_from_slice(key);
    Some(total)
}

/// Size of `pw_response_header`.
pub const PASSWD_HEADER: usize = 36;
/// Size of `gr_response_header`.
pub const GROUP_HEADER: usize = 24;
/// Size of `hst_response_header`.
pub const HOST_HEADER: usize = 32;
/// Size of `ai_response_header`.
pub const ADDRINFO_HEADER: usize = 24;
/// Size of `initgr_response_header`.
pub const INITGROUPS_HEADER: usize = 12;
/// Size of `serv_response_header`.
pub const SERVICE_HEADER: usize = 24;
/// Size of `netgroup_response_header`.
pub const NETGROUP_HEADER: usize = 16;
/// Size of `innetgroup_response_header`.
pub const INNETGROUP_HEADER: usize = 12;

/// Field `index` (counted in 32-bit words from the start) of a reply header.
pub fn field(header: &[u8], index: usize) -> i32 {
    let at = index * 4;
    match header.get(at..at + 4) {
        Some(b) => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

/// A count or length from a header as a size; None when the daemon sent a negative number.
pub fn size(header: &[u8], index: usize) -> Option<usize> {
    usize::try_from(field(header, index)).ok()
}

/// The `found` field (word 1) of every reply header.
pub fn found(header: &[u8]) -> i32 {
    field(header, 1)
}
