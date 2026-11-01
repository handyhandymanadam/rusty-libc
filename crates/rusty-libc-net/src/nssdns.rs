//! The answer parsers of the `dns` name service module: what glibc's nss_dns does with a DNS answer once the resolver has
//! sent the query. Host answers (A/AAAA, with CNAME chains), address-to-name answers (PTR), the A+AAAA pair of
//! `getaddrinfo`, the canonical-name walk and the network (in-addr.arpa) answers.
//!
//! Written from the behaviour of glibc 2.43 (what each case returns, in which order, with which `h_errno` and `errno`),
//! not from its text. Nothing here does I/O or allocates: a parser reads a `&[u8]` answer and reports what it finds to a
//! sink, so a caller can count first and fill second, and every branch can be tested with a hand-made packet.
//!
//! Quirks that are glibc's behaviour and are kept on purpose: the owner of a CNAME record is not checked (its target
//! becomes the name the next records must have), a QNAME or CNAME target that is not a valid host name is not reported as
//! an alias, an answer without any address is TRYAGAIN with NO_RECOVERY
//! (not NO_DATA), and the PTR parser never counts the answer records down (it reads on into the authority and additional
//! sections until it finds a PTR, or runs out of message).
use crate::dns::HErr;
use crate::nss::Status;
use crate::types::*;
use crate::util::Buf;
use crate::wire::*;
use core::ffi::c_int;

/// The longest host name accepted from an answer, in characters (nss_dns redefines MAXHOSTNAMELEN as 256, with a NUL after it;
/// a valid host name has no escaped characters, so the 255 bytes of a wire name always fit: this only guards the buffers).
pub const MAXHOST: usize = 256;

/// What a parser reports, in the terms of an NSS module function: its status, and the `h_errno` and `errno` it sets
/// (`None`: it leaves the caller's value alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    pub h_errno: Option<c_int>,
    pub errno: Option<c_int>,
}

fn out(status: Status, h_errno: c_int, errno: c_int) -> Outcome {
    Outcome { status, h_errno: Some(h_errno), errno: if errno == 0 { None } else { Some(errno) } }
}

// ---------------------------------------------------------------- when the query itself failed

/// What the host lookups do when the query (search) returned no usable answer, like the `n < 0` branch of glibc's
/// `_nss_dns_gethostbyname3_r`: no name server configured is TRYAGAIN; running out of descriptors, nothing listening and
/// no answer in time are UNAVAIL (the first with `h_errno` NETDB_INTERNAL, the others with what the resolver set, TRY_AGAIN);
/// anything else (the servers answered "no such name" or "no data") is NOTFOUND. `errno` is EAGAIN for a TRY_AGAIN
/// `h_errno` and the caller's own value otherwise (`None`).
pub fn query_failure(e: &HErr) -> Outcome {
    let (status, h) = match e.errno {
        ESRCH => (Status::TryAgain, TRY_AGAIN),
        EMFILE | ENFILE => (Status::Unavail, NETDB_INTERNAL),
        ECONNREFUSED | ETIMEDOUT => (Status::Unavail, e.h),
        _ => (Status::NotFound, e.h),
    };
    Outcome { status, h_errno: Some(h), errno: if h == TRY_AGAIN { Some(EAGAIN) } else { None } }
}

// ---------------------------------------------------------------- names in wire form

/// A wire-form name has only host-name characters in its labels and does not start with a dash.
pub fn bin_hnok(name: &[u8]) -> bool {
    if name.len() >= 2 && name[0] > 0 && name[1] == b'-' {
        return false;
    }
    let mut i = 0;
    loop {
        let l = match name.get(i) {
            Some(&0) | None => return true,
            Some(&l) => l as usize,
        };
        i += 1;
        for k in 0..l {
            match name.get(i + k) {
                Some(&c) if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' => {}
                _ => return false,
            }
        }
        i += l;
    }
}

/// Two uncompressed wire-form names are the same: equal label lengths, equal letters ignoring ASCII case.
pub fn bin_same(a: &[u8], b: &[u8]) -> bool {
    let (mut i, mut j) = (0, 0);
    loop {
        let (la, lb) = (a.get(i).copied().unwrap_or(0), b.get(j).copied().unwrap_or(0));
        if la == 0 || lb == 0 {
            return la == 0 && lb == 0;
        }
        if la != lb {
            return false;
        }
        for k in 1..=la as usize {
            let (x, y) = (a.get(i + k).copied().unwrap_or(0), b.get(j + k).copied().unwrap_or(0));
            if !x.eq_ignore_ascii_case(&y) {
                return false;
            }
        }
        i += 1 + la as usize;
        j += 1 + lb as usize;
    }
}

/// Length of the uncompressed name at the start of `s` (labels up to the root byte, root byte counted), within 255 bytes.
fn bin_len_uncompressed(s: &[u8]) -> Option<usize> {
    let mut p = 0;
    loop {
        let b = *s.get(p)? as usize;
        p += 1;
        if b == 0 {
            return if p > MAXCDNAME { None } else { Some(p) };
        }
        if b > 63 || b > s.len() - p {
            return None;
        }
        p += b;
    }
}

/// The text of a wire name for a host: only if it is a valid host name and fits in [`MAXHOST`] characters.
fn host_text(bin: &[u8]) -> Option<Buf<{ MAXHOST + 1 }>> {
    if !bin_hnok(bin) {
        return None;
    }
    name_ntop::<{ MAXHOST + 1 }>(bin).filter(|t| t.len <= MAXHOST)
}

// ---------------------------------------------------------------- reading records

/// One record, with its owner name unpacked to wire form (255 bytes at most, like glibc's `ns_rr_wire`).
#[derive(Clone, Copy)]
pub struct RrWire {
    pub rname: [u8; MAXCDNAME],
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: usize,
    pub rdlen: usize,
}

/// Reads the records of a message strictly: one question (not compressed), then record after record to the end of the
/// message, whatever the header counts say.
pub struct RrReader<'a> {
    pub msg: &'a [u8],
    pos: usize,
    pub rcode: u8,
    pub aa: bool,
    pub ancount: u16,
    /// Offset and length of the question name (uncompressed, root byte included).
    pub qname_off: usize,
    pub qname_len: usize,
    pub qtype: u16,
    pub qclass: u16,
}

impl<'a> RrReader<'a> {
    /// Fails (like glibc's `__ns_rr_cursor_init`) for a message under 12 bytes, a question count other than 1, a
    /// compressed or truncated QNAME, or no room for type and class.
    pub fn new(msg: &'a [u8]) -> Option<RrReader<'a>> {
        if msg.len() < HFIXEDSZ || msg[4] != 0 || msg[5] != 1 {
            return None;
        }
        let qlen = bin_len_uncompressed(&msg[HFIXEDSZ..])?;
        let after = HFIXEDSZ + qlen;
        if msg.len() - after < QFIXEDSZ {
            return None;
        }
        Some(RrReader {
            msg,
            pos: after + QFIXEDSZ,
            rcode: msg[3] & 0x0f,
            aa: msg[2] & 0x04 != 0,
            ancount: ((msg[6] as u16) << 8) | msg[7] as u16,
            qname_off: HFIXEDSZ,
            qname_len: qlen,
            qtype: get16(msg, after)?,
            qclass: get16(msg, after + 2)?,
        })
    }

    pub fn qname(&self) -> &'a [u8] {
        &self.msg[self.qname_off..self.qname_off + self.qname_len]
    }

    /// The next record, or `None` when the next bytes are not a whole record (also at the end of the message).
    pub fn next_rr(&mut self) -> Option<RrWire> {
        let mut rname = [0u8; MAXCDNAME];
        let used = name_unpack(self.msg, self.pos, &mut rname)?;
        let p = self.pos + used;
        if self.msg.len() - p < RRFIXEDSZ {
            return None;
        }
        let rdlen = get16(self.msg, p + 8)? as usize;
        if self.msg.len() - (p + RRFIXEDSZ) < rdlen {
            return None;
        }
        let rr = RrWire { rname, rtype: get16(self.msg, p)?, class: get16(self.msg, p + 2)?, ttl: get32(self.msg, p + 4)?, rdata: p + RRFIXEDSZ, rdlen };
        self.pos = rr.rdata + rdlen;
        Some(rr)
    }
}

/// The data length an address record of this type must have.
fn addr_len(qtype: u16) -> usize {
    match qtype {
        T_A => 4,
        T_AAAA => 16,
        _ => usize::MAX,
    }
}

fn lower_ttl(ttl: &mut i32, rr_ttl: u32) {
    // glibc keeps the minimum in a signed 32-bit value
    let t = rr_ttl as i32;
    if *ttl > t {
        *ttl = t;
    }
}

// ---------------------------------------------------------------- host answers (gethostbyname, gethostbyname2)

/// Receives what [`parse_host`] finds, in the order glibc would store it.
pub trait HostSink {
    /// A name for the host: the QNAME first, then each CNAME target that is a valid host name. The last one is the
    /// official name (`h_name`), the ones before it are the aliases.
    fn alias(&mut self, name: &[u8]);
    /// An address (4 or 16 bytes).
    fn addr(&mut self, a: &[u8]);
}

/// A host answer for `qtype` (A or AAAA), like glibc's `getanswer_r`. `ttl` takes the smallest TTL of the CNAME and
/// address records, and 0 for a negative result.
pub fn parse_host(pkt: &[u8], qtype: u16, sink: &mut dyn HostSink, ttl: &mut i32) -> Outcome {
    let Some(mut rd) = RrReader::new(pkt) else {
        return out(Status::Unavail, NO_RECOVERY, 0);
    };
    // the QNAME is treated like an alias; a QNAME that is no valid host name, or an NXDOMAIN, ends it
    let qname = rd.qname();
    let stored = if rd.rcode == NXDOMAIN { None } else { host_text(qname) };
    let Some(first) = stored else {
        *ttl = 0;
        return out(Status::NotFound, HOST_NOT_FOUND, ENOENT);
    };
    sink.alias(first.as_bytes());
    let mut expected = [0u8; MAXCDNAME];
    expected[..qname.len()].copy_from_slice(qname);
    let mut naddr = 0usize;
    for _ in 0..rd.ancount {
        let Some(rr) = rd.next_rr() else {
            return out(Status::Unavail, NO_RECOVERY, 0);
        };
        if rr.class != C_IN {
            continue;
        }
        if rr.rtype == T_CNAME || rr.rtype == qtype {
            lower_ttl(ttl, rr.ttl);
        }
        if rr.rtype == T_CNAME {
            // the owner is not compared; the target is what the following records have to be called
            let mut target = [0u8; MAXCDNAME];
            if name_unpack(pkt, rr.rdata, &mut target).is_none() {
                return out(Status::Unavail, NO_RECOVERY, 0);
            }
            if let Some(t) = host_text(&target) {
                sink.alias(t.as_bytes());
            }
            expected = target;
        } else if rr.rtype == qtype && bin_same(&rr.rname, &expected) && rr.rdlen == addr_len(qtype) {
            sink.addr(&pkt[rr.rdata..rr.rdata + rr.rdlen]);
            naddr += 1;
        }
    }
    if naddr == 0 {
        *ttl = 0;
        return out(Status::TryAgain, NO_RECOVERY, ENOENT);
    }
    out(Status::Success, NETDB_SUCCESS, 0)
}

// ---------------------------------------------------------------- address to name (gethostbyaddr)

/// A PTR answer, like glibc's `getanswer_ptr`: the first PTR record owned by the (CNAME-followed) query name gives the
/// host name, which is put in `name`. The parser does not count the answer section down: it goes on through authority
/// and additional records until it finds a PTR or the message ends (then UNAVAIL with NO_RECOVERY).
pub fn parse_ptr(pkt: &[u8], ttl: &mut i32, name: &mut Buf<{ MAXHOST + 1 }>) -> Outcome {
    let Some(mut rd) = RrReader::new(pkt) else {
        return out(Status::Unavail, NO_RECOVERY, 0);
    };
    let mut expected = [0u8; MAXCDNAME];
    let q = rd.qname();
    expected[..q.len()].copy_from_slice(q);
    // glibc's "expected name" points into the answer for the QNAME and into one scratch buffer after a CNAME; the scratch
    // buffer is then overwritten by the PTR target, so the host-name check below looks at the target in that case
    let mut expected_is_scratch = false;
    if rd.ancount > 0 {
        loop {
            let Some(rr) = rd.next_rr() else {
                return out(Status::Unavail, NO_RECOVERY, 0);
            };
            if rr.class != C_IN {
                continue;
            }
            if rr.rtype == T_CNAME || rr.rtype == T_PTR {
                lower_ttl(ttl, rr.ttl);
            }
            if rr.rtype == T_CNAME {
                if name_unpack(pkt, rr.rdata, &mut expected).is_none() {
                    return out(Status::Unavail, NO_RECOVERY, 0);
                }
                expected_is_scratch = true;
            } else if rr.rtype == T_PTR && bin_same(&rr.rname, &expected) {
                let mut target = [0u8; MAXCDNAME];
                let unpacked = name_unpack(pkt, rr.rdata, &mut target).is_some();
                let checked: &[u8] = if expected_is_scratch { &target } else { &expected };
                let text = if unpacked && bin_hnok(checked) { name_ntop::<{ MAXHOST + 1 }>(&target).filter(|t| t.len <= MAXHOST) } else { None };
                let Some(t) = text else {
                    return out(Status::Unavail, NO_RECOVERY, 0);
                };
                *name = t;
                return out(Status::Success, NETDB_SUCCESS, 0);
            }
        }
    }
    *ttl = 0;
    out(Status::TryAgain, NO_RECOVERY, ENOENT)
}

// ---------------------------------------------------------------- A and AAAA together (getaddrinfo)

/// Receives the address tuples of [`parse_a_aaaa`].
pub trait TupleSink {
    /// One address (`family` AF_INET with 4 bytes, AF_INET6 with 16). `canon` is the canonical name, given with the
    /// first tuple of the first answer that has a usable name.
    fn tuple(&mut self, family: c_int, addr: &[u8], canon: Option<&[u8]>);
    /// The sink ran out of room: stop and report TRYAGAIN (the caller then grows its buffer and tries again).
    fn failed(&self) -> bool {
        false
    }
}

/// One answer of the pair, like glibc's `gaih_getanswer_slice`. Records of any class count here.
fn gaih_slice(pkt: &[u8], sink: &mut dyn TupleSink, ttl: &mut i32, mut store_canon: bool) -> Outcome {
    let Some(mut rd) = RrReader::new(pkt) else {
        return out(Status::Unavail, NO_RECOVERY, 0);
    };
    let qtype = rd.qtype;
    let q = rd.qname();
    if rd.ancount == 0 || !bin_hnok(q) {
        return out(Status::NotFound, HOST_NOT_FOUND, 0);
    }
    let mut expected = [0u8; MAXCDNAME];
    expected[..q.len()].copy_from_slice(q);
    // where the canonical name is: the QNAME, then the data of the last CNAME whose target is a valid host name
    let mut canon_at: Option<usize> = Some(rd.qname_off);
    let mut have = false;
    for _ in 0..rd.ancount {
        let Some(rr) = rd.next_rr() else {
            return out(Status::Unavail, NO_RECOVERY, 0);
        };
        if rr.rtype == T_CNAME || rr.rtype == qtype {
            lower_ttl(ttl, rr.ttl);
        }
        if rr.rtype == T_CNAME {
            let mut target = [0u8; MAXCDNAME];
            if name_unpack(pkt, rr.rdata, &mut target).is_none() {
                return out(Status::Unavail, NO_RECOVERY, 0);
            }
            expected = target;
            if store_canon && bin_hnok(&target) {
                canon_at = Some(rr.rdata);
            }
        } else if rr.rtype == qtype && bin_same(&rr.rname, &expected) && rr.rdlen == addr_len(qtype) {
            let mut canon: Option<Buf<{ MAXHOST + 1 }>> = None;
            if store_canon {
                if let Some(at) = canon_at {
                    let mut bin = [0u8; MAXCDNAME];
                    if name_unpack(pkt, at, &mut bin).is_some() {
                        canon = name_ntop::<{ MAXHOST + 1 }>(&bin).filter(|t| t.len <= MAXHOST);
                    }
                    store_canon = false;
                }
            }
            let family = if rr.rdlen == 4 { AF_INET } else { AF_INET6 };
            sink.tuple(family, &pkt[rr.rdata..rr.rdata + rr.rdlen], canon.as_ref().map(|c| c.as_bytes()));
            have = true;
        }
    }
    if have {
        out(Status::Success, NETDB_SUCCESS, 0)
    } else {
        // only CNAMEs while looking for addresses
        out(Status::NotFound, HOST_NOT_FOUND, 0)
    }
}

/// The answers to an A query and an AAAA query together, like glibc's `gaih_getanswer`: the first answer decides unless
/// it was not a success and the second answer is something other than NOTFOUND. `h_errno` is the one of the answer parsed
/// last. Pass `None` for the second packet when only A was asked (RES_NOAAAA).
pub fn parse_a_aaaa(p1: &[u8], p2: Option<&[u8]>, sink: &mut dyn TupleSink, ttl: &mut i32) -> Outcome {
    let mut res = out(Status::NotFound, NETDB_SUCCESS, 0);
    if !p1.is_empty() {
        res = gaih_slice(p1, sink, ttl, true);
        if sink.failed() {
            return out(Status::TryAgain, res.h_errno.unwrap_or(NETDB_SUCCESS), 0);
        }
    }
    if let Some(p2) = p2 {
        if matches!(res.status, Status::Success | Status::NotFound) && !p2.is_empty() {
            let first = res.status;
            let r2 = gaih_slice(p2, sink, ttl, first != Status::Success);
            res.h_errno = r2.h_errno;
            if first != Status::Success && r2.status != Status::NotFound {
                res.status = r2.status;
            }
        }
    }
    res
}

// ---------------------------------------------------------------- canonical name (getcanonname)

/// How a canonical-name walk over one answer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Canon {
    /// The first record of the wanted type is owned by the name at this offset of the message.
    Found(usize),
    /// Nothing usable in this answer: try the next record type.
    Next,
    /// The answer is malformed or has a record that is neither the wanted type nor a CNAME: give up.
    Unavail,
}

/// glibc's `getcanonname` walk: skips CNAME records of class IN and takes the owner name of the first record of type
/// `qtype`. Any other record type, a CNAME of another class or a record that does not fit ends the walk with UNAVAIL.
pub fn canon_walk(pkt: &[u8], qtype: u16) -> Canon {
    if pkt.len() < HFIXEDSZ || pkt[4] != 0 || pkt[5] != 1 {
        return Canon::Next;
    }
    let mut ancount = ((pkt[6] as usize) << 8) | pkt[7] as usize;
    let Some(after_q) = name_skip(pkt, HFIXEDSZ) else { return Canon::Unavail };
    let mut p = after_q + 4;
    while ancount > 0 {
        ancount -= 1;
        let start = p;
        let Some(q) = name_skip(pkt, p) else { return Canon::Unavail };
        p = q;
        if pkt.len().saturating_sub(p) < 10 {
            return Canon::Unavail;
        }
        let ty = get16(pkt, p).unwrap_or(0);
        p += 2;
        if ty == qtype {
            return Canon::Found(start);
        }
        if ty != T_CNAME {
            return Canon::Unavail;
        }
        if get16(pkt, p).unwrap_or(0) != C_IN {
            return Canon::Unavail;
        }
        p += 2 + 4;
        let rdlen = get16(pkt, p).unwrap_or(0) as usize;
        p += 2;
        if pkt.len().saturating_sub(p) < rdlen {
            return Canon::Unavail;
        }
        p += rdlen;
    }
    Canon::Next
}

// ---------------------------------------------------------------- networks (getnetbyname, getnetbyaddr)

/// Which network lookup an answer is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetBy {
    Addr,
    Name,
}

/// Names a network answer can carry: the buffer of glibc's parser holds 48 pointers, which leaves room for 46 names.
pub const MAX_NET_NAMES: usize = 46;

/// The network answer parser (glibc's BIND-style `getanswer_r` of nss_dns/dns-network.c). `line_room` is the number of bytes
/// the caller's buffer has for text after its pointer table; each PTR target stored takes its length plus one and the
/// owner name of every record is written at the current position first, so a name that does not fit gives ERANGE
/// (`TryAgain`, `h_errno` NETDB_INTERNAL, errno ERANGE). Each stored target (a valid host name) goes to `name`.
pub fn parse_net(pkt: &[u8], line_room: usize, name: &mut dyn FnMut(&[u8])) -> Outcome {
    let too_small = || out(Status::TryAgain, NETDB_INTERNAL, ERANGE);
    if pkt.len() < HFIXEDSZ {
        return out(Status::Unavail, NO_RECOVERY, 0);
    }
    let mut questions = ((pkt[4] as usize) << 8) | pkt[5] as usize;
    let mut answers = ((pkt[6] as i32) << 8) | pkt[7] as i32;
    if questions == 0 {
        return if pkt[2] & 0x04 != 0 { out(Status::NotFound, HOST_NOT_FOUND, 0) } else { out(Status::TryAgain, TRY_AGAIN, 0) };
    }
    let mut cp = HFIXEDSZ;
    while questions > 0 {
        questions -= 1;
        match name_skip(pkt, cp) {
            Some(n) if pkt.len() - n >= QFIXEDSZ => cp = n + QFIXEDSZ,
            _ => return out(Status::Unavail, NO_RECOVERY, 0),
        }
    }
    let mut room = line_room;
    let mut stored = 0usize;
    let mut have_answer = false;
    loop {
        answers -= 1;
        if answers < 0 || cp >= pkt.len() {
            break;
        }
        // the owner name is written at the current position (it takes room, but is not kept)
        let mut bin = [0u8; MAXCDNAME];
        let Some(n) = name_unpack(pkt, cp, &mut bin) else { break };
        let Some(text) = name_ntop::<MAXDNAME_TEXT>(&bin) else { break };
        if text.len + 1 > room {
            return too_small();
        }
        cp += n;
        if pkt.len() - cp < RRFIXEDSZ {
            return out(Status::Unavail, NO_RECOVERY, 0);
        }
        let ty = get16(pkt, cp).unwrap_or(0);
        let class = get16(pkt, cp + 2).unwrap_or(0);
        let rdlen = get16(pkt, cp + 8).unwrap_or(0) as usize;
        cp += RRFIXEDSZ;
        if pkt.len() - cp < rdlen {
            return out(Status::Unavail, NO_RECOVERY, 0);
        }
        if class == C_IN && ty == T_PTR {
            let mut tb = [0u8; MAXCDNAME];
            let ok = name_unpack(pkt, cp, &mut tb).is_some();
            let tt = if ok { name_ntop::<MAXDNAME_TEXT>(&tb) } else { None };
            if let Some(t) = &tt {
                if t.len + 1 > room {
                    return too_small();
                }
            }
            // a target that cannot be read or is no valid host name ends the whole parse
            let Some(t) = tt.filter(|_| bin_hnok(&tb)) else {
                return Outcome { status: Status::Unavail, h_errno: None, errno: None };
            };
            cp += rdlen;
            if stored < MAX_NET_NAMES {
                name(t.as_bytes());
                room -= t.len + 1;
                stored += 1;
                have_answer = true;
            }
        } else {
            cp += rdlen;
        }
    }
    if have_answer {
        return out(Status::Success, NETDB_SUCCESS, 0);
    }
    out(Status::TryAgain, TRY_AGAIN, 0)
}

const MAXDNAME_TEXT: usize = 1025;

/// For a lookup by name: the network number written in one of the stored names, `d.c.b.a.in-addr.arpa` (up to four
/// numbers, each in decimal, octal with a leading 0 or hexadecimal with 0x, the first one the least significant byte).
pub fn net_from_name(name: &[u8]) -> Option<u32> {
    let at = |i: usize| name.get(i).copied().unwrap_or(0);
    let mut p = 0usize;
    let mut val = 0u32;
    let mut shift = 0u32;
    loop {
        let mut base = 10u32;
        if at(p) == b'0' && at(p + 1) != b'.' {
            base = 8;
            p += 1;
            if at(p) == b'x' || at(p) == b'X' {
                base = 16;
                p += 1;
                if at(p) == b'.' {
                    return None;
                }
            }
            if at(p) == 0 {
                return None;
            }
        }
        let mut part = 0u32;
        loop {
            let c = at(p);
            if c.is_ascii_digit() && ((c - b'0') as u32) < base {
                part = part.wrapping_mul(base).wrapping_add((c - b'0') as u32);
            } else if base == 16 && c.is_ascii_hexdigit() {
                part = (part << 4).wrapping_add(10 + (c.to_ascii_lowercase() - b'a') as u32);
            }
            p += 1;
            if at(p) == 0 || at(p) == b'.' {
                break;
            }
        }
        if at(p) != b'.' {
            return None;
        }
        val |= part << shift;
        shift += 8;
        p += 1;
        if !at(p).is_ascii_digit() && name.get(p..).is_some_and(|r| r.eq_ignore_ascii_case(b"in-addr.arpa")) {
            return Some(val);
        }
        if shift >= 32 {
            return None;
        }
    }
}

/// The query name of a network lookup by number (class A, B, C, or a full address by the number of significant bytes),
/// like `_nss_dns_getnetbyaddr_r`.
pub fn net_query_name(net: u32) -> Buf<64> {
    let b = net.to_be_bytes();
    let first = b.iter().position(|&x| x != 0);
    let mut q = Buf::<64>::new();
    match first {
        // the default network
        None => {
            q.push_all(b"0.0.0.0");
        }
        Some(first) => {
            // zero labels for the missing high bytes, then the significant bytes, last one first
            for _ in 0..first {
                q.push_all(b"0.");
            }
            for i in (first..4).rev() {
                q.push_u32(b[i] as u32);
                if i != first {
                    q.push(b'.');
                }
            }
        }
    }
    q.push_all(b".in-addr.arpa");
    q
}

/// The query name of an address to name lookup: `d.c.b.a.in-addr.arpa`, or the 32 nibbles under `ip6.arpa`.
pub fn reverse_query_name(family: c_int, addr: &[u8]) -> Buf<80> {
    crate::dns::reverse_name(family, addr)
}
