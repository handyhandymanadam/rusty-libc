//! The nss_dns answer parsers on hand-made packets: every branch of what glibc does with an answer.
use crate::nss::Status;
use crate::nssdns::*;
use crate::types::*;
use crate::util::Buf;
use crate::wire::*;

fn wname(n: &str) -> Vec<u8> {
    let mut o = vec![];
    for l in n.trim_end_matches('.').split('.') {
        if l.is_empty() {
            continue;
        }
        o.push(l.len() as u8);
        o.extend_from_slice(l.as_bytes());
    }
    o.push(0);
    o
}

struct R {
    owner: String,
    ty: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn rr(owner: &str, ty: u16, rdata: Vec<u8>) -> R {
    R { owner: owner.into(), ty, class: C_IN, ttl: 300, rdata }
}
fn a(owner: &str, ip: [u8; 4]) -> R {
    rr(owner, T_A, ip.to_vec())
}
fn aaaa(owner: &str, last: u8) -> R {
    let mut v = [0u8; 16];
    v[0] = 0x20;
    v[1] = 0x01;
    v[15] = last;
    rr(owner, T_AAAA, v.to_vec())
}
fn cname(owner: &str, target: &str) -> R {
    rr(owner, T_CNAME, wname(target))
}
fn ptr(owner: &str, target: &str) -> R {
    rr(owner, T_PTR, wname(target))
}

/// A response: header, one question, then the answer and authority records.
fn msg(qname: &str, qtype: u16, rcode: u8, aa: bool, an: &[R], ns: &[R]) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    Header { id: 7, flags: 0x8000 | 0x0100 | 0x0080 | (if aa { 0x0400 } else { 0 }) | rcode as u16, qdcount: 1, ancount: an.len() as u16, nscount: ns.len() as u16, arcount: 0 }.write(&mut m);
    m.extend(wname(qname));
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for r in an.iter().chain(ns.iter()) {
        m.extend(wname(&r.owner));
        m.extend_from_slice(&r.ty.to_be_bytes());
        m.extend_from_slice(&r.class.to_be_bytes());
        m.extend_from_slice(&r.ttl.to_be_bytes());
        m.extend_from_slice(&(r.rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&r.rdata);
    }
    m
}

#[derive(Default)]
struct HS {
    aliases: Vec<String>,
    addrs: Vec<Vec<u8>>,
}
impl HostSink for HS {
    fn alias(&mut self, n: &[u8]) {
        self.aliases.push(String::from_utf8_lossy(n).into_owned());
    }
    fn addr(&mut self, a: &[u8]) {
        self.addrs.push(a.to_vec());
    }
}

fn host(pkt: &[u8], qtype: u16) -> (Outcome, HS, i32) {
    let mut s = HS::default();
    let mut ttl = i32::MAX;
    let o = parse_host(pkt, qtype, &mut s, &mut ttl);
    (o, s, ttl)
}

fn is(o: Outcome, st: Status, h: Option<i32>, e: Option<i32>) {
    assert_eq!((o.status, o.h_errno, o.errno), (st, h, e), "{o:?}");
}

#[test]
fn host_plain_answer() {
    let m = msg("www.example.com", T_A, 0, false, &[a("www.example.com", [192, 0, 2, 1]), a("www.example.com", [192, 0, 2, 2])], &[]);
    let (o, s, ttl) = host(&m, T_A);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.aliases, ["www.example.com"]);
    assert_eq!(s.addrs, [vec![192, 0, 2, 1], vec![192, 0, 2, 2]]);
    assert_eq!(ttl, 300);
}

#[test]
fn host_cname_chain_owner_is_not_checked() {
    // the first CNAME has an owner that is not the query name: glibc follows it anyway
    let m = msg(
        "a.example",
        T_A,
        0,
        false,
        &[cname("zzz.other", "b.example"), cname("b.example", "c.example"), a("c.example", [10, 0, 0, 1]), a("b.example", [10, 0, 0, 2])],
        &[],
    );
    let (o, s, _) = host(&m, T_A);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.aliases, ["a.example", "b.example", "c.example"]);
    // the address owned by b.example no longer matches (the expected name moved on to c.example)
    assert_eq!(s.addrs, [vec![10, 0, 0, 1]]);
}

#[test]
fn host_answer_without_address_is_tryagain_no_recovery() {
    let m = msg("a.example", T_A, 0, false, &[cname("a.example", "b.example")], &[]);
    let (o, _, ttl) = host(&m, T_A);
    is(o, Status::TryAgain, Some(NO_RECOVERY), Some(ENOENT));
    assert_eq!(ttl, 0);
}

#[test]
fn host_nxdomain_and_bad_qname() {
    let m = msg("a.example", T_A, 3, false, &[], &[]);
    let (o, s, ttl) = host(&m, T_A);
    is(o, Status::NotFound, Some(HOST_NOT_FOUND), Some(ENOENT));
    assert!(s.aliases.is_empty());
    assert_eq!(ttl, 0);
    // a QNAME with a character that is no host name character
    let m = msg("a b.example", T_A, 0, false, &[a("a b.example", [1, 2, 3, 4])], &[]);
    let (o, s, _) = host(&m, T_A);
    is(o, Status::NotFound, Some(HOST_NOT_FOUND), Some(ENOENT));
    assert!(s.addrs.is_empty());
    // a leading dash is refused too
    let m = msg("-a.example", T_A, 0, false, &[a("-a.example", [1, 2, 3, 4])], &[]);
    is(host(&m, T_A).0, Status::NotFound, Some(HOST_NOT_FOUND), Some(ENOENT));
}

#[test]
fn host_names_of_any_valid_length_are_fine() {
    // nss_dns allows host names up to 256 characters: a 79 character name is an alias and an owner like any other
    let long = format!("{}.{}.example", "a".repeat(40), "b".repeat(30));
    assert_eq!(long.len(), 79);
    let m = msg(&long, T_A, 0, false, &[a(&long, [1, 2, 3, 4])], &[]);
    let (o, s, _) = host(&m, T_A);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.aliases, [long.as_str()]);
    // a name of 252 characters in four labels of 63
    let l = "x".repeat(62);
    let longest = format!("{l}1.{l}2.{l}3.{}", "y".repeat(60));
    assert_eq!(longest.len(), 252);
    let m = msg(&longest, T_A, 0, false, &[a(&longest, [1, 2, 3, 4])], &[]);
    let (o, s, _) = host(&m, T_A);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.aliases, [longest.as_str()]);
}

#[test]
fn host_skips_other_class_wrong_owner_and_wrong_length() {
    let mut other = a("a.example", [9, 9, 9, 9]);
    other.class = 3; // CH
    let wrong_owner = a("b.example", [8, 8, 8, 8]);
    let short = rr("a.example", T_A, vec![1, 2, 3]);
    let long = rr("a.example", T_A, vec![1, 2, 3, 4, 5]);
    let good = a("A.EXAMPLE", [1, 1, 1, 1]); // owner compared ignoring case
    let m = msg("a.example", T_A, 0, false, &[other, wrong_owner, short, long, good], &[]);
    let (o, s, _) = host(&m, T_A);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.addrs, [vec![1, 1, 1, 1]]);
}

#[test]
fn host_ttl_is_the_minimum_of_cname_and_address_records() {
    let mut c = cname("a.example", "b.example");
    c.ttl = 50;
    let mut x = a("b.example", [1, 1, 1, 1]);
    x.ttl = 120;
    let mut y = a("b.example", [1, 1, 1, 2]);
    y.ttl = 80;
    let mut other = rr("b.example", T_AAAA, vec![0; 16]);
    other.ttl = 5; // another type: not counted
    let m = msg("a.example", T_A, 0, false, &[c, x, y, other], &[]);
    let (_, _, ttl) = host(&m, T_A);
    assert_eq!(ttl, 50);
}

#[test]
fn host_malformed_answers() {
    // a record cut short
    let m = msg("a.example", T_A, 0, false, &[a("a.example", [1, 2, 3, 4])], &[]);
    let cut = &m[..m.len() - 2];
    is(host(cut, T_A).0, Status::Unavail, Some(NO_RECOVERY), None);
    // ancount larger than the records present
    let mut m2 = m.clone();
    m2[7] = 3;
    is(host(&m2, T_A).0, Status::Unavail, Some(NO_RECOVERY), None);
    // two questions
    let mut m3 = m.clone();
    m3[5] = 2;
    is(host(&m3, T_A).0, Status::Unavail, Some(NO_RECOVERY), None);
    // shorter than a header
    is(host(&m[..8], T_A).0, Status::Unavail, Some(NO_RECOVERY), None);
    // a compressed question name
    let mut m4 = m.clone();
    m4[12] = 0xc0;
    m4[13] = 0x0c;
    is(host(&m4, T_A).0, Status::Unavail, Some(NO_RECOVERY), None);
}

#[test]
fn host_compressed_owner_and_cname_target() {
    // owner of the first record is a pointer to the question name; the CNAME target points into the question too
    let mut m = msg("www.example.com", T_AAAA, 0, false, &[], &[]);
    m[7] = 2;
    // record 1: owner = pointer to offset 12, CNAME, rdata = "real" + pointer to "example.com" (offset 12+4)
    m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 0x2c, 0, 7, 4, b'r', b'e', b'a', b'l', 0xc0, 16]);
    // record 2: owner = real.example.com via pointer to the rdata of record 1, AAAA
    let off = m.len() - 7; // the start of "4 real" in the rdata of record 1
    m.extend_from_slice(&[0xc0, off as u8, 0, 28, 0, 1, 0, 0, 1, 0x2c, 0, 16]);
    m.extend_from_slice(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    let (o, s, _) = host(&m, T_AAAA);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.aliases, ["www.example.com", "real.example.com"]);
    assert_eq!(s.addrs.len(), 1);
    assert_eq!(s.addrs[0][15], 9);
}

// ------------------------------------------------------------------ PTR

fn ptr_of(pkt: &[u8]) -> (Outcome, String, i32) {
    let mut ttl = i32::MAX;
    let mut n = Buf::<{ MAXHOST + 1 }>::new();
    let o = parse_ptr(pkt, &mut ttl, &mut n);
    (o, String::from_utf8_lossy(n.as_bytes()).into_owned(), ttl)
}

const REV: &str = "1.2.0.192.in-addr.arpa";

#[test]
fn ptr_finds_first_ptr() {
    let m = msg(REV, T_PTR, 0, false, &[ptr(REV, "host.example"), ptr(REV, "other.example")], &[]);
    let (o, n, ttl) = ptr_of(&m);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(n, "host.example");
    assert_eq!(ttl, 300);
}

#[test]
fn ptr_follows_cname_and_checks_the_target_name() {
    let m = msg(REV, T_PTR, 0, false, &[cname(REV, "c.in-addr.arpa"), ptr("c.in-addr.arpa", "host.example")], &[]);
    let (o, n, _) = ptr_of(&m);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(n, "host.example");
    // after a CNAME the host-name check looks at the PTR target (glibc's scratch buffer is shared): a bad target fails
    let m = msg(REV, T_PTR, 0, false, &[cname(REV, "c.in-addr.arpa"), ptr("c.in-addr.arpa", "bad host.example")], &[]);
    is(ptr_of(&m).0, Status::Unavail, Some(NO_RECOVERY), None);
    // without a CNAME the check looks at the query name, so a bad PTR target passes (and is printed with an escape)
    let m = msg(REV, T_PTR, 0, false, &[ptr(REV, "bad host.example")], &[]);
    let (o, n, _) = ptr_of(&m);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(n, "bad\\032host.example");
}

#[test]
fn ptr_does_not_count_the_answer_section_down() {
    // no PTR in the answer section but one in the authority section: found there
    let m = msg(REV, T_PTR, 0, false, &[a("x.example", [1, 1, 1, 1])], &[ptr(REV, "late.example")]);
    let (o, n, _) = ptr_of(&m);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(n, "late.example");
    // no PTR anywhere: the walk runs off the end of the message
    let m = msg(REV, T_PTR, 0, false, &[a("x.example", [1, 1, 1, 1])], &[]);
    is(ptr_of(&m).0, Status::Unavail, Some(NO_RECOVERY), None);
    // an empty answer section: tryagain with the ttl cleared
    let m = msg(REV, T_PTR, 0, false, &[], &[]);
    let (o, _, ttl) = ptr_of(&m);
    is(o, Status::TryAgain, Some(NO_RECOVERY), Some(ENOENT));
    assert_eq!(ttl, 0);
}

#[test]
fn ptr_long_name_is_fine() {
    let long = format!("{}.{}.example", "a".repeat(40), "b".repeat(30));
    let m = msg(REV, T_PTR, 0, false, &[ptr(REV, &long)], &[]);
    let (o, n, _) = ptr_of(&m);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(n, long);
}

// ------------------------------------------------------------------ A and AAAA together

#[derive(Default)]
struct TS {
    t: Vec<(i32, Vec<u8>, Option<String>)>,
    full: bool,
}
impl TupleSink for TS {
    fn tuple(&mut self, family: i32, addr: &[u8], canon: Option<&[u8]>) {
        self.t.push((family, addr.to_vec(), canon.map(|c| String::from_utf8_lossy(c).into_owned())));
    }
    fn failed(&self) -> bool {
        self.full
    }
}

fn pair(p1: &[u8], p2: Option<&[u8]>) -> (Outcome, TS) {
    let mut s = TS::default();
    let mut ttl = i32::MAX;
    let o = parse_a_aaaa(p1, p2, &mut s, &mut ttl);
    (o, s)
}

#[test]
fn pair_success_both_and_canonical_name_on_first_tuple() {
    let p1 = msg("n.example", T_A, 0, false, &[cname("n.example", "c.example"), a("c.example", [1, 1, 1, 1])], &[]);
    let p2 = msg("n.example", T_AAAA, 0, false, &[cname("n.example", "c.example"), aaaa("c.example", 2)], &[]);
    let (o, s) = pair(&p1, Some(&p2));
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.t.len(), 2);
    assert_eq!(s.t[0].0, AF_INET);
    assert_eq!(s.t[0].2.as_deref(), Some("c.example"));
    assert_eq!(s.t[1].0, AF_INET6);
    assert_eq!(s.t[1].2, None);
}

#[test]
fn pair_first_notfound_second_success_stores_the_name_from_the_second() {
    // the first answer is only a CNAME (NOTFOUND); the second has the address and the canonical name
    let p1 = msg("n.example", T_A, 0, false, &[cname("n.example", "c.example")], &[]);
    let p2 = msg("n.example", T_AAAA, 0, false, &[cname("n.example", "d.example"), aaaa("d.example", 2)], &[]);
    let (o, s) = pair(&p1, Some(&p2));
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.t.len(), 1);
    assert_eq!(s.t[0].2.as_deref(), Some("d.example"));
}

#[test]
fn pair_status_table() {
    let ok = |q: &str, ty| msg(q, ty, 0, false, &[if ty == T_A { a(q, [1, 1, 1, 1]) } else { aaaa(q, 1) }], &[]);
    let nf = |q: &str, ty| msg(q, ty, 0, false, &[cname(q, "z.example")], &[]); // only a CNAME: NOTFOUND
    let un = |q: &str, ty| {
        let mut m = ok(q, ty);
        m.truncate(m.len() - 3); // record cut short: UNAVAIL
        m
    };
    let n = "n.example";
    // first success: the second answer is ignored, h_errno is the second slice's
    let (o, _) = pair(&ok(n, T_A), Some(&un(n, T_AAAA)));
    assert_eq!(o.status, Status::Success);
    assert_eq!(o.h_errno, Some(NO_RECOVERY), "the second answer's h_errno replaces the first's, as in glibc");
    let (o, _) = pair(&ok(n, T_A), Some(&nf(n, T_AAAA)));
    assert_eq!(o.status, Status::Success);
    // first notfound: the second decides unless it is notfound too
    assert_eq!(pair(&nf(n, T_A), Some(&ok(n, T_AAAA))).0.status, Status::Success);
    assert_eq!(pair(&nf(n, T_A), Some(&nf(n, T_AAAA))).0.status, Status::NotFound);
    assert_eq!(pair(&nf(n, T_A), Some(&un(n, T_AAAA))).0.status, Status::Unavail);
    // first unavail: the second is not looked at
    assert_eq!(pair(&un(n, T_A), Some(&ok(n, T_AAAA))).0.status, Status::Unavail);
    // no second answer (RES_NOAAAA)
    assert_eq!(pair(&ok(n, T_A), None).0.status, Status::Success);
    assert_eq!(pair(&nf(n, T_A), None).0.status, Status::NotFound);
}

#[test]
fn pair_no_answers_or_bad_name_is_notfound() {
    let m = msg("n.example", T_A, 0, false, &[], &[]);
    is(pair(&m, None).0, Status::NotFound, Some(HOST_NOT_FOUND), None);
    let m = msg("n e.example", T_A, 0, false, &[a("n e.example", [1, 1, 1, 1])], &[]);
    is(pair(&m, None).0, Status::NotFound, Some(HOST_NOT_FOUND), None);
}

#[test]
fn pair_counts_any_class_and_follows_cname_last_wins() {
    let mut x = a("c2.example", [1, 1, 1, 1]);
    x.class = 3; // this parser does not look at the class
    let m = msg("n.example", T_A, 0, false, &[cname("x", "c1.example"), cname("y", "c2.example"), x], &[]);
    let (o, s) = pair(&m, None);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(s.t[0].2.as_deref(), Some("c2.example"));
}

#[test]
fn pair_full_sink_gives_tryagain() {
    let p1 = msg("n.example", T_A, 0, false, &[a("n.example", [1, 1, 1, 1])], &[]);
    let p2 = msg("n.example", T_AAAA, 0, false, &[aaaa("n.example", 1)], &[]);
    let mut s = TS { full: true, ..Default::default() };
    let mut ttl = i32::MAX;
    let o = parse_a_aaaa(&p1, Some(&p2), &mut s, &mut ttl);
    assert_eq!(o.status, Status::TryAgain);
    assert_eq!(s.t.len(), 1, "the second answer is not parsed");
}

// ------------------------------------------------------------------ canonical name

#[test]
fn canon_walk_cases() {
    let m = msg("n.example", T_A, 0, false, &[cname("n.example", "c.example"), a("c.example", [1, 1, 1, 1])], &[]);
    let at = match canon_walk(&m, T_A) {
        Canon::Found(at) => at,
        x => panic!("{x:?}"),
    };
    let name = name_expand::<256>(&m, at).unwrap().0;
    assert_eq!(name.as_bytes(), b"c.example");
    // wrong type first record (an RRSIG): give up
    let m = msg("n.example", T_A, 0, false, &[rr("n.example", 46, vec![0; 20]), a("n.example", [1, 1, 1, 1])], &[]);
    assert_eq!(canon_walk(&m, T_A), Canon::Unavail);
    // empty answer: next type
    let m = msg("n.example", T_A, 0, false, &[], &[]);
    assert_eq!(canon_walk(&m, T_A), Canon::Next);
    // CNAME of another class
    let mut c = cname("n.example", "c.example");
    c.class = 3;
    let m = msg("n.example", T_A, 0, false, &[c], &[]);
    assert_eq!(canon_walk(&m, T_A), Canon::Unavail);
    // two questions: next type
    let mut m = msg("n.example", T_A, 0, false, &[], &[]);
    m[5] = 2;
    assert_eq!(canon_walk(&m, T_A), Canon::Next);
    // a record that does not fit
    let m = msg("n.example", T_A, 0, false, &[cname("n.example", "c.example")], &[]);
    assert_eq!(canon_walk(&m[..m.len() - 3], T_A), Canon::Unavail);
}

// ------------------------------------------------------------------ networks

fn net(pkt: &[u8], room: usize) -> (Outcome, Vec<String>) {
    let mut v = vec![];
    let o = parse_net(pkt, room, &mut |n: &[u8]| v.push(String::from_utf8_lossy(n).into_owned()));
    (o, v)
}

#[test]
fn net_names_and_status() {
    let q = "code5.example";
    let m = msg(q, T_PTR, 0, false, &[ptr(q, "127.in-addr.arpa"), ptr(q, "0.in-addr.arpa")], &[]);
    let (o, v) = net(&m, 1000);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(v, ["127.in-addr.arpa", "0.in-addr.arpa"]);
    // an answer section without a PTR: tryagain, h_errno TRY_AGAIN
    let m = msg(q, T_PTR, 0, false, &[], &[]);
    is(net(&m, 1000).0, Status::TryAgain, Some(TRY_AGAIN), None);
    // a record of another type is skipped (RRSIG-like)
    let m = msg(q, T_PTR, 0, false, &[ptr(q, "127.in-addr.arpa"), rr(q, 46, vec![0x3f; 500]), ptr(q, "0.in-addr.arpa")], &[]);
    assert_eq!(net(&m, 1000).1.len(), 2);
    // a target that is no host name ends the parse with UNAVAIL and leaves h_errno alone
    let m = msg(q, T_PTR, 0, false, &[ptr(q, "bad name.example")], &[]);
    is(net(&m, 1000).0, Status::Unavail, None, None);
    // no room: ERANGE
    let m = msg(q, T_PTR, 0, false, &[ptr(q, "127.in-addr.arpa")], &[]);
    is(net(&m, 5).0, Status::TryAgain, Some(NETDB_INTERNAL), Some(ERANGE));
    // truncated record data
    let m = msg(q, T_PTR, 0, false, &[ptr(q, "127.in-addr.arpa")], &[]);
    is(net(&m[..m.len() - 3], 1000).0, Status::Unavail, Some(NO_RECOVERY), None);
    // question count 0: authoritative answer is HOST_NOT_FOUND, otherwise TRY_AGAIN
    let mut m = msg(q, T_PTR, 0, true, &[], &[]);
    m[5] = 0;
    is(net(&m, 1000).0, Status::NotFound, Some(HOST_NOT_FOUND), None);
    m[2] &= !0x04;
    is(net(&m, 1000).0, Status::TryAgain, Some(TRY_AGAIN), None);
}

#[test]
fn net_at_most_46_names() {
    let q = "q.example";
    let recs: Vec<R> = (0..60).map(|i| ptr(q, &format!("{i}.in-addr.arpa"))).collect();
    let m = msg(q, T_PTR, 0, false, &recs, &[]);
    let (o, v) = net(&m, 10000);
    is(o, Status::Success, Some(NETDB_SUCCESS), None);
    assert_eq!(v.len(), MAX_NET_NAMES);
}

#[test]
fn net_number_from_name() {
    assert_eq!(net_from_name(b"1.in-addr.arpa"), Some(1));
    assert_eq!(net_from_name(b"2.1.in-addr.arpa"), Some(0x0102));
    assert_eq!(net_from_name(b"3.2.1.in-addr.arpa"), Some(0x010203));
    assert_eq!(net_from_name(b"4.3.2.1.in-addr.arpa"), Some(0x01020304));
    assert_eq!(net_from_name(b"127.in-addr.arpa"), Some(0x7f));
    assert_eq!(net_from_name(b"0.in-addr.arpa"), Some(0));
    assert_eq!(net_from_name(b"0x10.in-addr.arpa"), Some(16));
    assert_eq!(net_from_name(b"010.in-addr.arpa"), Some(8));
    assert_eq!(net_from_name(b"1.IN-ADDR.ARPA"), Some(1));
    assert_eq!(net_from_name(b"host.example"), None);
    assert_eq!(net_from_name(b"1.2.example"), None);
    assert_eq!(net_from_name(b"0x.in-addr.arpa"), None);
}

#[test]
fn net_query_names() {
    assert_eq!(net_query_name(0).as_bytes(), b"0.0.0.0.in-addr.arpa");
    assert_eq!(net_query_name(0x7f).as_bytes(), b"0.0.0.127.in-addr.arpa");
    assert_eq!(net_query_name(0x0102).as_bytes(), b"0.0.2.1.in-addr.arpa");
    assert_eq!(net_query_name(0x010203).as_bytes(), b"0.3.2.1.in-addr.arpa");
    assert_eq!(net_query_name(0x01020304).as_bytes(), b"4.3.2.1.in-addr.arpa");
}
