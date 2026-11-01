//! The resolver against a fake name server on 127.0.0.1 (a std thread; no network access).
use super::*;
use crate::dns::{self, Config, HostData, Server};
use crate::types::*;
use crate::wire;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the fake server does with one query.
pub enum Reply {
    Drop,
    Raw(Vec<u8>),
    /// Over TCP: close the connection without an answer.
    Close,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Seen {
    pub name: String,
    pub qtype: u16,
    pub tcp: bool,
    pub arcount: u16,
    /// The OPT record of the query, if it has one: (UDP payload size, flags).
    pub opt: Option<(u16, u16)>,
}

pub struct Fake {
    pub port: u16,
    pub log: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn name_wire(n: &str) -> Vec<u8> {
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

pub struct Rec {
    pub owner: &'static str,
    pub ty: u16,
    pub rdata: Vec<u8>,
}

pub fn a(owner: &'static str, ip: [u8; 4]) -> Rec {
    Rec { owner, ty: wire::T_A, rdata: ip.to_vec() }
}
pub fn aaaa(owner: &'static str, ip: &str) -> Rec {
    Rec { owner, ty: wire::T_AAAA, rdata: ip.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec() }
}
pub fn cname(owner: &'static str, target: &str) -> Rec {
    Rec { owner, ty: wire::T_CNAME, rdata: name_wire(target) }
}
pub fn ptr(owner: &'static str, target: &str) -> Rec {
    Rec { owner, ty: wire::T_PTR, rdata: name_wire(target) }
}

/// A response message echoing the question of `query`.
pub fn response(query: &[u8], rcode: u8, tc: bool, recs: &[Rec]) -> Vec<u8> {
    let id = wire::get16(query, 0).unwrap();
    let mut m = vec![0u8; 12];
    wire::Header { id, flags: 0x8000 | 0x0100 | 0x0080 | (if tc { 0x0200 } else { 0 }) | rcode as u16, qdcount: 1, ancount: recs.len() as u16, nscount: 0, arcount: 0 }.write(&mut m);
    // the question as the query sent it (byte for byte: a name with a space or a dot inside a label stays the same name)
    let mut end = 12;
    while query[end] != 0 {
        end += 1 + query[end] as usize;
    }
    m.extend_from_slice(&query[12..end + 1 + 4]);
    for r in recs {
        m.extend(name_wire(r.owner));
        m.extend_from_slice(&r.ty.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        m.extend_from_slice(&(r.rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&r.rdata);
    }
    m
}

fn seen_of(q: &[u8], tcp: bool) -> Option<Seen> {
    let (n, t, _) = wire::first_question::<256>(q)?;
    let h = wire::Header::parse(q)?;
    // the OPT record is the last 11 bytes of a query that has one: root name, type, class = size, ttl (rcode, version, flags), rdlen
    let opt = if h.arcount == 1 && q.len() >= 11 + 12 {
        let o = &q[q.len() - 11..];
        (o[0] == 0 && wire::get16(o, 1) == Some(wire::T_OPT)).then(|| (wire::get16(o, 3).unwrap(), wire::get16(o, 7).unwrap()))
    } else {
        None
    };
    Some(Seen { name: String::from_utf8_lossy(n.as_bytes()).into_owned(), qtype: t, tcp, arcount: h.arcount, opt })
}

impl Fake {
    /// Start a server; `handler(seen, id)` returns the datagrams (or TCP messages) to send back.
    pub fn start(handler: impl Fn(&Seen, &[u8]) -> Vec<Reply> + Send + Sync + 'static) -> Fake {
        let h: Arc<dyn Fn(&Seen, &[u8]) -> Vec<Reply> + Send + Sync> = Arc::new(handler);
        let (udp, tcp, port) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = udp.local_addr().unwrap().port();
            if let Ok(t) = TcpListener::bind(("127.0.0.1", port)) {
                break (udp, t, port);
            }
        };
        udp.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = vec![];
        {
            let (h, log, stop) = (h.clone(), log.clone(), stop.clone());
            threads.push(std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::SeqCst) {
                    let Ok((n, from)) = udp.recv_from(&mut buf) else { continue };
                    let Some(seen) = seen_of(&buf[..n], false) else { continue };
                    log.lock().unwrap().push(seen.clone());
                    for r in h(&seen, &buf[..n]) {
                        if let Reply::Raw(m) = r {
                            let _ = udp.send_to(&m, from);
                        }
                    }
                }
            }));
        }
        {
            let (h, log, stop) = (h.clone(), log.clone(), stop.clone());
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut s, _)) = tcp.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    s.set_nonblocking(false).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    // every query on the connection (a pair comes on one), until the client closes it
                    'conn: loop {
                        let mut lb = [0u8; 2];
                        if s.read_exact(&mut lb).is_err() {
                            break;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                        if s.read_exact(&mut q).is_err() {
                            break;
                        }
                        let Some(seen) = seen_of(&q, true) else { break };
                        log.lock().unwrap().push(seen.clone());
                        for r in h(&seen, &q) {
                            match r {
                                Reply::Raw(m) => {
                                    let _ = s.write_all(&(m.len() as u16).to_be_bytes());
                                    let _ = s.write_all(&m);
                                }
                                Reply::Close => break 'conn,
                                Reply::Drop => {}
                            }
                        }
                    }
                }
            }));
        }
        Fake { port, log, stop, threads }
    }
    pub fn server(&self) -> Server {
        Server::v4([127, 0, 0, 1], self.port)
    }
    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn cfg_for(f: &Fake) -> Config {
    let mut c = Config::with_servers(&[f.server()]);
    c.timeout_ms = 300;
    c.attempts = 2;
    c
}

/// The `dns` source of the hosts database (what getaddrinfo and gethostbyname ask), as a Result: Err carries the `h_errno`.
fn lookup(cfg: &Config, name: &str, af: c_int) -> Result<HostData, dns::HErr> {
    let mut hd = HostData::new();
    let (st, h) = crate::netdb::dns_hosts(cfg, name.as_bytes(), af, &mut hd);
    if st == crate::nss::Status::Success { Ok(hd) } else { Err(dns::HErr { h, rcode: 0, errno: 0 }) }
}

fn status(cfg: &Config, name: &str, af: c_int) -> (crate::nss::Status, c_int) {
    let mut hd = HostData::new();
    crate::netdb::dns_hosts(cfg, name.as_bytes(), af, &mut hd)
}

fn zone(seen: &Seen, q: &[u8]) -> Vec<Reply> {
    let recs: Vec<Rec> = match (seen.name.as_str(), seen.qtype) {
        ("www.example.test", t) if t == wire::T_A || t == wire::T_AAAA => {
            let mut v = vec![cname("www.example.test", "web.example.test")];
            if t == wire::T_A {
                v.push(a("web.example.test", [192, 0, 2, 1]));
                v.push(a("web.example.test", [192, 0, 2, 2]));
            } else {
                v.push(aaaa("web.example.test", "2001:db8::1"));
            }
            v
        }
        ("v4only.example.test", t) if t == wire::T_A => vec![a("v4only.example.test", [192, 0, 2, 7])],
        ("v4only.example.test", _) => vec![],
        ("4.3.2.1.in-addr.arpa", wire::T_PTR) => vec![ptr("4.3.2.1.in-addr.arpa", "host1234.example.test")],
        ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", wire::T_PTR) => vec![ptr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "six.example.test")],
        _ => return vec![Reply::Raw(response(q, wire::NXDOMAIN, false, &[]))],
    };
    vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))]
}

#[test]
fn a_aaaa_cname_chains() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let cfg = cfg_for(&f);
    let hd = lookup(&cfg, "www.example.test", AF_INET).unwrap();
    assert_eq!(hd.canon.as_bytes(), b"web.example.test");
    assert_eq!(hd.n, 2);
    assert_eq!((hd.addrs[0].family, &hd.addrs[0].bytes[..4]), (AF_INET, &[192u8, 0, 2, 1][..]));
    assert_eq!(&hd.addrs[1].bytes[..4], &[192, 0, 2, 2]);
    assert_eq!(hd.aliases.as_bytes(), b"www.example.test\0");
    let hd = lookup(&cfg, "www.example.test", AF_INET6).unwrap();
    assert_eq!(hd.n, 1);
    assert_eq!(hd.addrs[0].bytes, "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    // a name that exists but has no AAAA: NOERROR with no data
    let e = lookup(&cfg, "v4only.example.test", AF_INET6).err().unwrap();
    assert_eq!(e.h, NO_DATA);
    // unknown name
    let e = lookup(&cfg, "nosuch.example.test", AF_INET).err().unwrap();
    assert_eq!(e.h, HOST_NOT_FOUND);
    // queries went out as UDP with the recursion flag, one per question
    assert!(f.seen().iter().all(|s| !s.tcp));
}

#[test]
fn truncated_udp_answer_is_retried_over_tcp() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| {
        if s.name == "big.example.test" {
            if s.tcp {
                let recs: Vec<Rec> = (0..60u8).map(|i| a("big.example.test", [192, 0, 2, i])).collect();
                return vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))];
            }
            return vec![Reply::Raw(response(q, wire::NOERROR, true, &[]))];
        }
        zone(s, q)
    });
    let cfg = cfg_for(&f);
    let hd = lookup(&cfg, "big.example.test", AF_INET).unwrap();
    assert_eq!(hd.n, 60);
    let seen = f.seen();
    assert_eq!(seen.iter().filter(|s| !s.tcp).count(), 1);
    assert_eq!(seen.iter().filter(|s| s.tcp).count(), 1);
}

#[test]
fn timeouts_and_server_failover() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // a server that never answers: both attempts time out, the result is TRY_AGAIN
    let silent = Fake::start(|_, _| vec![Reply::Drop]);
    let mut cfg = cfg_for(&silent);
    cfg.timeout_ms = 150;
    let t0 = Instant::now();
    let e = lookup(&cfg, "slow.example.test", AF_INET).err().unwrap();
    let el = t0.elapsed();
    assert_eq!(e.h, TRY_AGAIN);
    // glibc's rule: the first server gets `retrans << 0` on every try (no doubling for it), so two tries of 150 ms
    assert!(el >= Duration::from_millis(290) && el < Duration::from_secs(3), "elapsed {el:?}");
    assert_eq!(silent.seen().len(), 2, "two attempts");
    // first server says SERVFAIL, the second answers
    let bad = Fake::start(|_, q| vec![Reply::Raw(response(q, wire::SERVFAIL, false, &[]))]);
    let good = Fake::start(zone);
    let mut cfg = Config::with_servers(&[bad.server(), good.server()]);
    cfg.timeout_ms = 300;
    let hd = lookup(&cfg, "v4only.example.test", AF_INET).unwrap();
    assert_eq!(&hd.addrs[0].bytes[..4], &[192, 0, 2, 7]);
    assert_eq!(bad.seen().len(), 1);
    // every server SERVFAIL: TRY_AGAIN
    let cfg = Config::with_servers(&[bad.server()]);
    let e = lookup(&cfg, "v4only.example.test", AF_INET).err().unwrap();
    assert_eq!(e.h, TRY_AGAIN);
    // REFUSED from every server is TRY_AGAIN too, like glibc (a failed send), not NO_RECOVERY
    let refuse = Fake::start(|_, q| vec![Reply::Raw(response(q, wire::REFUSED, false, &[]))]);
    let e = lookup(&Config::with_servers(&[refuse.server()]), "x.example.test", AF_INET).err().unwrap();
    assert_eq!(e.h, TRY_AGAIN);
}

#[test]
fn a_name_of_the_longest_length_resolves() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // four labels of 63, 63, 63 and 61 characters: 253 characters, 255 bytes on the wire
    let long: &'static str = Box::leak(format!("{}x.{}y.{}z.{}t", "a".repeat(62), "a".repeat(62), "a".repeat(62), "a".repeat(60)).into_boxed_str());
    assert_eq!(long.len(), 252 + 1);
    let f = Fake::start(move |s, q| {
        let recs = if s.name == long { vec![if s.qtype == wire::T_A { a(long, [192, 0, 2, 20]) } else { aaaa(long, "2001:db8::4") }] } else { vec![] };
        vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))]
    });
    let cfg = cfg_for(&f);
    for af in [AF_INET, AF_INET6] {
        let hd = lookup(&cfg, long, af).unwrap_or_else(|e| panic!("af {af}: {e:?}"));
        assert_eq!(hd.n, 1);
        assert_eq!(hd.canon.as_bytes(), long.as_bytes());
    }
    let hd = lookup(&cfg, long, AF_UNSPEC).unwrap();
    assert_eq!(hd.n, 2);
}

#[test]
fn dns_source_status_and_h_errno_follow_glibc() {
    use crate::nss::Status::*;
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| match s.name.as_str() {
        // only a CNAME, no address record
        "cnameonly.example.test" => vec![Reply::Raw(response(q, wire::NOERROR, false, &[cname("cnameonly.example.test", "x.example.test")]))],
        "refused.example.test" => vec![Reply::Raw(response(q, wire::REFUSED, false, &[]))],
        "servfail.example.test" => vec![Reply::Raw(response(q, wire::SERVFAIL, false, &[]))],
        "formerr.example.test" => vec![Reply::Raw(response(q, wire::FORMERR, false, &[]))],
        "dual.example.test" => {
            let recs = if s.qtype == wire::T_A { vec![a("dual.example.test", [10, 0, 0, 1])] } else { vec![aaaa("dual.example.test", "2001:db8::2")] };
            vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))]
        }
        "a-only.example.test" => {
            if s.qtype == wire::T_A { vec![Reply::Raw(response(q, wire::NOERROR, false, &[a("a-only.example.test", [10, 0, 0, 3])]))] } else { vec![Reply::Raw(response(q, wire::NOERROR, false, &[]))] }
        }
        _ => zone(s, q),
    });
    let mut cfg = cfg_for(&f);
    cfg.timeout_ms = 100;
    cfg.attempts = 1;
    assert_eq!(status(&cfg, "www.example.test", AF_INET), (Success, NETDB_SUCCESS));
    assert_eq!(status(&cfg, "nosuch.example.test", AF_INET), (NotFound, HOST_NOT_FOUND));
    assert_eq!(status(&cfg, "v4only.example.test", AF_INET6), (NotFound, NO_DATA));
    // an answer with no address in it: TRYAGAIN, NO_RECOVERY (not NO_DATA)
    assert_eq!(status(&cfg, "cnameonly.example.test", AF_INET), (TryAgain, NO_RECOVERY));
    // FORMERR is an answer: NOTFOUND, NO_RECOVERY
    assert_eq!(status(&cfg, "formerr.example.test", AF_INET), (NotFound, NO_RECOVERY));
    // every server failing to give a usable answer: UNAVAIL with TRY_AGAIN
    assert_eq!(status(&cfg, "refused.example.test", AF_INET), (Unavail, TRY_AGAIN));
    assert_eq!(status(&cfg, "servfail.example.test", AF_INET), (Unavail, TRY_AGAIN));
    // a name that cannot be a host name is not asked
    let before = f.seen().len();
    assert_eq!(status(&cfg, "bad name.example.test", AF_INET), (NotFound, HOST_NOT_FOUND));
    assert_eq!(f.seen().len(), before);
    // both families
    assert_eq!(status(&cfg, "dual.example.test", AF_UNSPEC), (Success, NETDB_SUCCESS));
    let hd = lookup(&cfg, "dual.example.test", AF_UNSPEC).unwrap();
    assert_eq!(hd.n, 2);
    assert_eq!(hd.addrs[0].family, AF_INET);
    assert_eq!(hd.addrs[1].family, AF_INET6);
    // only A has data: still a success, and h_errno is what the parser said of the empty AAAA answer (HOST_NOT_FOUND), as
    // glibc's _nss_dns_gethostbyname4_r leaves it (compared with the host's in nssdnsabitest)
    assert_eq!(status(&cfg, "a-only.example.test", AF_UNSPEC), (Success, HOST_NOT_FOUND));
    // both queries NXDOMAIN
    assert_eq!(status(&cfg, "nosuch.example.test", AF_UNSPEC), (NotFound, HOST_NOT_FOUND));
    // A has data and AAAA is empty: a success (h_errno as above)
    assert_eq!(status(&cfg, "v4only.example.test", AF_UNSPEC), (Success, HOST_NOT_FOUND));
    // RES_NOAAAA: only the A query goes out
    let mut c2 = cfg;
    c2.options |= dns::RES_NOAAAA;
    f.log.lock().unwrap().clear();
    assert_eq!(status(&c2, "dual.example.test", AF_UNSPEC), (Success, NETDB_SUCCESS));
    assert_eq!(f.seen().iter().map(|s| s.qtype).collect::<Vec<_>>(), [wire::T_A]);
    // RES_NOAAAA, an AAAA query: asked as A (glibc's __res_handle_no_aaaa), the answer is an AAAA one with no records
    f.log.lock().unwrap().clear();
    assert_eq!(status(&c2, "dual.example.test", AF_INET6), (NotFound, NO_DATA));
    assert_eq!(status(&c2, "nosuch.example.test", AF_INET6), (NotFound, HOST_NOT_FOUND));
    assert_eq!(f.seen().iter().map(|s| s.qtype).collect::<Vec<_>>(), [wire::T_A, wire::T_A]);
    let mut buf = [0u8; 512];
    let n = dns::query(&c2, b"dual.example.test", wire::C_IN, wire::T_AAAA, &mut buf);
    assert_eq!(n.map_err(|e| e.h), Err(NO_DATA));
    let (_, qt, qc) = wire::first_question::<256>(&buf).unwrap();
    assert_eq!((qt, qc), (wire::T_AAAA, wire::C_IN));
    assert_eq!(&buf[6..12], &[0; 6]);
    // nothing listening: UNAVAIL, TRY_AGAIN
    let closed = Fake::start(|_, _| vec![]);
    let port_server = closed.server();
    drop(closed);
    let mut c3 = Config::with_servers(&[port_server]);
    c3.timeout_ms = 100;
    c3.attempts = 1;
    assert_eq!(status(&c3, "x.example.test", AF_INET), (Unavail, TRY_AGAIN));
}

#[test]
fn bogus_answers_are_ignored_until_the_right_one_arrives() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| {
        let mut wrong_id = response(q, wire::NOERROR, false, &[a("v4only.example.test", [6, 6, 6, 6])]);
        wrong_id[0] ^= 0xff;
        let mut wrong_name = q.to_vec();
        let _ = &mut wrong_name;
        let wrong_q = {
            let mut qq = q.to_vec();
            // change the question type so it does not match
            let n = qq.len();
            qq[n - 3] = 99;
            response(&qq, wire::NOERROR, false, &[a("v4only.example.test", [7, 7, 7, 7])])
        };
        let mut out = vec![Reply::Raw(wrong_id), Reply::Raw(wrong_q)];
        out.extend(zone(s, q));
        out
    });
    let cfg = cfg_for(&f);
    let hd = lookup(&cfg, "v4only.example.test", AF_INET).unwrap();
    assert_eq!(hd.n, 1);
    assert_eq!(&hd.addrs[0].bytes[..4], &[192, 0, 2, 7]);
}

#[test]
fn search_list_and_ndots() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| {
        match s.name.as_str() {
            "app.b.test" | "x.y.b.test" | "x.y" => vec![Reply::Raw(response(q, wire::NOERROR, false, &[a(Box::leak(s.name.clone().into_boxed_str()), [10, 0, 0, 1])]))],
            _ => vec![Reply::Raw(response(q, wire::NXDOMAIN, false, &[]))],
        }
    });
    let mut cfg = cfg_for(&f);
    cfg.search[0] = crate::util::Buf::from(b"a.test").unwrap();
    cfg.search[1] = crate::util::Buf::from(b"b.test").unwrap();
    cfg.nsearch = 2;
    // no dot: the search list first, the bare name last
    lookup(&cfg, "app", AF_INET).unwrap();
    let names: Vec<String> = f.seen().into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["app.a.test", "app.b.test"]);
    f.log.lock().unwrap().clear();
    // ndots 1 and one dot: the name as it is first
    lookup(&cfg, "x.y", AF_INET).unwrap();
    assert_eq!(f.seen().into_iter().map(|s| s.name).collect::<Vec<_>>(), ["x.y"]);
    f.log.lock().unwrap().clear();
    // ndots 2: x.y is tried with the suffixes before as is
    cfg.ndots = 2;
    lookup(&cfg, "x.y", AF_INET).unwrap();
    assert_eq!(f.seen().into_iter().map(|s| s.name).collect::<Vec<_>>(), ["x.y.a.test", "x.y.b.test"]);
    f.log.lock().unwrap().clear();
    // a trailing dot means "absolute": no search at all
    assert!(lookup(&cfg, "app.", AF_INET).is_err());
    assert_eq!(f.seen().into_iter().map(|s| s.name).collect::<Vec<_>>(), ["app"], "one query, no search list");
    f.log.lock().unwrap().clear();
    // without RES_DNSRCH only the bare name is asked
    cfg.options &= !dns::RES_DNSRCH;
    cfg.ndots = 1;
    assert!(lookup(&cfg, "p.q", AF_INET).is_err());
    assert_eq!(f.seen().len(), 1);
    f.log.lock().unwrap().clear();
    // a root entry in the search list ("." or "") stands for the bare name: glibc does not ask it again at the end
    cfg.options |= dns::RES_DNSRCH;
    cfg.search[1] = crate::util::Buf::from(b".").unwrap();
    assert!(lookup(&cfg, "zz", AF_INET).is_err());
    assert_eq!(f.seen().into_iter().map(|s| s.name).collect::<Vec<_>>(), ["zz.a.test", "zz"]);
}

#[test]
fn hostaliases_file_applies_to_names_without_dots() {
    // glibc's res_context_search and nss_dns: a name without a dot is first looked up in the $HOSTALIASES file (rootfs trial: the
    // aliases were ignored, "shortcut" was asked as shortcut.<search domain> and shortcut)
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let mut cfg = cfg_for(&f);
    cfg.search[0] = crate::util::Buf::from(b"example.test").unwrap();
    cfg.nsearch = 1;
    let path = std::env::temp_dir().join(format!("rusty-libc-hostaliases-{}", std::process::id()));
    std::fs::write(&path, "short www.example.test\nv4 v4only.example.test.\n").unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("HOSTALIASES", &path);
    }
    let hd = lookup(&cfg, "short", AF_INET);
    let names: Vec<String> = f.seen().into_iter().map(|s| s.name).collect();
    f.log.lock().unwrap().clear();
    let hd2 = lookup(&cfg, "v4", AF_INET);
    let names2: Vec<String> = f.seen().into_iter().map(|s| s.name).collect();
    // a name with a dot is not an alias candidate
    f.log.lock().unwrap().clear();
    let _ = lookup(&cfg, "short.x", AF_INET);
    let names3: Vec<String> = f.seen().into_iter().map(|s| s.name).collect();
    #[allow(unused_unsafe)]
    unsafe {
        std::env::remove_var("HOSTALIASES");
    }
    let _ = std::fs::remove_file(&path);
    assert_eq!(names, ["www.example.test"], "only the alias target is asked");
    assert_eq!(hd.unwrap().canon.as_bytes(), b"web.example.test");
    assert_eq!(names2, ["v4only.example.test"]);
    assert_eq!(hd2.unwrap().n, 1);
    assert!(!names3.iter().any(|n| n.contains("www.example.test")), "dotted names are not aliased: {names3:?}");
}

#[test]
fn edns0_option_adds_an_opt_record() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let mut cfg = cfg_for(&f);
    cfg.options |= dns::RES_USE_EDNS0;
    lookup(&cfg, "v4only.example.test", AF_INET).unwrap();
    assert_eq!(f.seen()[0].arcount, 1);
    // the name service lookups advertise 1200 and do not set the DO bit
    assert_eq!(f.seen()[0].opt, Some((1200, 0)));
}

#[test]
fn dnssec_option_adds_an_opt_record_with_the_do_bit() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let mut cfg = cfg_for(&f);
    // RES_USE_DNSSEC alone (without edns0) also sends an OPT record, with DO
    cfg.options |= dns::RES_USE_DNSSEC;
    lookup(&cfg, "v4only.example.test", AF_INET).unwrap();
    assert_eq!(f.seen()[0].opt, Some((1200, 0x8000)));
}

#[test]
fn advertised_size_follows_the_answer_buffer_like_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(wire::edns_payload(100), 512);
    assert_eq!(wire::edns_payload(512), 512);
    assert_eq!(wire::edns_payload(700), 700);
    assert_eq!(wire::edns_payload(1200), 1200);
    assert_eq!(wire::edns_payload(65536), 1200);
    let f = Fake::start(zone);
    let mut cfg = cfg_for(&f);
    cfg.options |= dns::RES_USE_EDNS0;
    let mut ans = [0u8; 4096];
    // res_nquery-style: the caller's buffer length is what is advertised
    dns::query_adv(&cfg, b"v4only.example.test", wire::C_IN, wire::T_A, &mut ans, 700).unwrap();
    dns::query_adv(&cfg, b"v4only.example.test", wire::C_IN, wire::T_A, &mut ans, 100).unwrap();
    dns::search_adv(&cfg, b"v4only.example.test", wire::C_IN, wire::T_A, &mut ans, 900).unwrap();
    let seen = f.seen();
    assert_eq!(seen[0].opt, Some((700, 0)));
    assert_eq!(seen[1].opt, Some((512, 0)));
    assert_eq!(seen[2].opt, Some((900, 0)));
}

#[test]
fn query_builder_writes_the_opt_bytes() {
    let mut q = [0u8; 600];
    let n = wire::build_query(1, b"a.test", wire::T_A, wire::C_IN, true, Some(wire::Opt { payload: 1200, dnssec_ok: true }), &mut q).unwrap();
    let opt = &q[n - 11..n];
    assert_eq!(opt, &[0, 0, 41, 0x04, 0xb0, 0, 0, 0x80, 0, 0, 0]);
    assert_eq!(wire::Header::parse(&q[..n]).unwrap().arcount, 1);
    let n2 = wire::build_query(1, b"a.test", wire::T_A, wire::C_IN, true, None, &mut q).unwrap();
    assert_eq!(n2, n - 11);
    assert_eq!(wire::Header::parse(&q[..n2]).unwrap().arcount, 0);
}

#[test]
fn resolver_flag_values_are_glibcs() {
    assert_eq!(dns::RES_USE_DNSSEC, 0x0080_0000);
    assert_eq!(dns::RES_STRICTERR, 0x1000_0000);
}

#[test]
fn resolv_conf_text_is_parsed_like_glibc() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let text = b"# comment\n; another\nnameserver 192.0.2.1\nnameserver 2001:db8::53\nnameserver 192.0.2.3\nnameserver 192.0.2.4\nsearch a.example b.example  c.example\noptions ndots:3 timeout:7 attempts:4 rotate edns0 use-vc single-request no-aaaa bogus-option\nsortlist 10.0.0.0/8\n";
    let c = Config::parse(text);
    assert_eq!(c.nservers, 3, "at most three servers");
    assert_eq!(c.servers[0], Server::v4([192, 0, 2, 1], 53));
    assert_eq!(c.servers[1].family, AF_INET6);
    assert_eq!(c.nsearch, 3);
    assert_eq!(c.search[2].as_bytes(), b"c.example");
    assert_eq!((c.ndots, c.timeout_ms, c.attempts), (3, 7000, 4));
    for bit in [dns::RES_ROTATE, dns::RES_USE_EDNS0, dns::RES_USEVC, dns::RES_SNGLKUP, dns::RES_NOAAAA] {
        assert!(c.options & bit != 0, "option {bit:#x}");
    }
    // limits: ndots 15, timeout 30, attempts 5; domain replaces search and the last of the two wins
    let c = Config::parse(b"options ndots:99 timeout:99 attempts:99\nsearch x.example\ndomain y.example\n");
    assert_eq!((c.ndots, c.timeout_ms, c.attempts), (15, 30000, 5));
    assert_eq!((c.nsearch, c.search[0].as_bytes()), (1, &b"y.example"[..]));
    let c = Config::parse(b"domain y.example\nsearch x.example z.example\n");
    assert_eq!((c.nsearch, c.search[0].as_bytes()), (2, &b"x.example"[..]));
    // no servers: the local host
    let mut c = Config::parse(b"search only.example\n");
    c.finish();
    assert_eq!((c.nservers, c.servers[0]), (1, Server::v4([127, 0, 0, 1], 53)));
}

#[test]
fn resolv_options_follow_glibc_res_setoptions() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let opts = |file: &str, env: Option<&str>| Config::parse_env(file.as_bytes(), None, env.map(str::as_bytes));
    // prefix matching, '-' clears, the later word wins, unknown words (and glibc 2.43's dropped ones) do nothing
    let c = opts("options rotatex single-request-reopenfoo no_tld_query strict-error debug no-check-names inet6\n", None);
    let want = dns::RES_DEFAULT | dns::RES_ROTATE | dns::RES_SNGLKUPREOP | dns::RES_NOTLDQUERY | dns::RES_STRICTERR;
    assert_eq!(c.options, want);
    let c = opts("options rotate edns0\n", Some("-rotate --edns0 - use-vc"));
    assert_eq!(c.options, dns::RES_DEFAULT | dns::RES_USE_EDNS0 | dns::RES_USEVC);
    // strtol: blanks before the number, no digits is 0, negative values kept (ndots in 4 bits), caps but no floor
    let c = opts("options ndots: 5 timeout:-1 attempts:abc\n", None);
    assert_eq!((c.ndots, c.timeout_ms, c.attempts), (5, -1000, 0));
    let c = opts("options ndots:-1 timeout:4294967298 attempts:99\n", None);
    assert_eq!((c.ndots, c.timeout_ms, c.attempts), (15, 2000, 5));
    // RES_OPTIONS after the file; the keyword needs a blank after it
    let c = opts("optionsrotate\noptions\tndots:4\n", Some("ndots:2"));
    assert_eq!((c.options, c.ndots), (dns::RES_DEFAULT, 2));
    // LOCALDOMAIN replaces the file's search list, an empty value too (one empty name)
    let c = Config::parse_env(b"search f.example\n", Some(b""), None);
    assert_eq!((c.nsearch, c.search[0].as_bytes()), (1, &b""[..]));
    let c = Config::parse_env(b"search f.example\n", Some(b"a.example\tb.example\nc.example"), None);
    assert_eq!((c.nsearch, c.search[1].as_bytes()), (2, &b"b.example"[..]));
    // inet_aton forms for servers, at most three; a line must start with its keyword
    let c = Config::parse(b" nameserver 10.0.0.9\nnameserver 127.1\nnameserver 10.0.0.300\n");
    assert_eq!((c.nservers, c.servers[0]), (1, Server::v4([127, 0, 0, 1], 53)));
    // sortlist: masks, the classful default, ten entries at most
    let c = Config::parse(b"sortlist 10.0.0.0/255.255.0.0 130.1.0.0 1.2.3.4&bad\n");
    assert_eq!(c.nsort, 3);
    assert_eq!(c.sort[1], (u32::from_ne_bytes([130, 1, 0, 0]), u32::from_ne_bytes([255, 255, 0, 0])));
    assert_eq!(c.sort[2].1, u32::from_ne_bytes([255, 0, 0, 0]));
}

#[test]
fn nsswitch_order_parsing() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use crate::nss::{Action, Source, Status, parse_order};
    let o = parse_order(b" files dns").unwrap();
    assert_eq!((o.n, o.e[0].src, o.e[1].src), (2, Source::Files, Source::Dns));
    assert_eq!(o.e[0].action(Status::Success), Action::Return);
    assert_eq!(o.e[0].action(Status::NotFound), Action::Continue);
    let o = parse_order(b"files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns").unwrap();
    assert_eq!((o.n, o.e[0].src, o.e[1].src), (2, Source::Files, Source::Dns), "unknown sources are skipped with their action lists");
    assert_eq!(o.e[1].action(Status::NotFound), Action::Continue);
    let o = parse_order(b"dns [!UNAVAIL=return] files").unwrap();
    assert_eq!(o.e[0].action(Status::NotFound), Action::Return);
    assert_eq!(o.e[0].action(Status::Unavail), Action::Continue);
    let o = parse_order(b"files [NOTFOUND=return] dns").unwrap();
    assert_eq!(o.e[0].action(Status::NotFound), Action::Return);
    assert!(parse_order(b"nis ldap").is_none());
    assert!(parse_order(b"").is_none());
}

/// A private etc with `hosts: dns` and the library's default resolver pointed at the fake server.
fn dns_only_world(f: &Fake) -> EtcGuard {
    let g = EtcGuard::with_files(&[("nsswitch.conf", "hosts: dns\n"), ("hosts", "")]);
    let mut c = cfg_for(f);
    c.options |= dns::RES_NORELOAD;
    dns::set_default_config(c);
    g
}

#[test]
fn getaddrinfo_getnameinfo_and_gethostbyname_through_dns() {
    let _l = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let _w = dns_only_world(&f);
    // getaddrinfo, both families, with the canonical name
    let hints = addrinfo { ai_flags: AI_CANONNAME, ai_socktype: SOCK_STREAM, ..addrinfo::default() };
    let mut res: *mut addrinfo = core::ptr::null_mut();
    let n = cs("www.example.test");
    let s = cs("8080");
    assert_eq!(unsafe { crate::gai::getaddrinfo(n.as_ptr(), s.as_ptr(), &hints, &mut res) }, 0);
    let mut seen = vec![];
    let mut p = res;
    while !p.is_null() {
        unsafe {
            let sa = crate::rustapi::SockAddr::from_raw(&*((*p).ai_addr as *const sockaddr_storage), (*p).ai_addrlen).unwrap();
            seen.push((sa.format().as_bytes().to_vec(), (*p).ai_socktype));
            p = (*p).ai_next;
        }
    }
    assert_eq!(cstr_opt(unsafe { (*res).ai_canonname }).as_deref(), Some("web.example.test"));
    unsafe { crate::gai::freeaddrinfo(res) };
    let texts: Vec<String> = seen.iter().map(|(t, _)| String::from_utf8(t.clone()).unwrap()).collect();
    assert_eq!(texts.len(), 3);
    for want in ["192.0.2.1:8080", "192.0.2.2:8080", "[2001:db8::1]:8080"] {
        assert!(texts.iter().any(|t| t == want), "{want} in {texts:?}");
    }
    // AF_INET only, and the name that does not exist
    let hints = addrinfo { ai_family: AF_INET, ..addrinfo::default() };
    let mut res: *mut addrinfo = core::ptr::null_mut();
    assert_eq!(unsafe { crate::gai::getaddrinfo(n.as_ptr(), core::ptr::null(), &hints, &mut res) }, 0);
    let mut cnt = 0;
    let mut p = res;
    while !p.is_null() {
        cnt += 1;
        p = unsafe { (*p).ai_next };
    }
    assert_eq!(cnt, 2 * 3, "two addresses, three socket types");
    unsafe { crate::gai::freeaddrinfo(res) };
    let nx = cs("nosuch.example.test");
    let mut res: *mut addrinfo = core::ptr::null_mut();
    assert_eq!(unsafe { crate::gai::getaddrinfo(nx.as_ptr(), core::ptr::null(), core::ptr::null(), &mut res) }, EAI_NONAME);
    // a name with only IPv4 asked for IPv6: EAI_NODATA
    let v4 = cs("v4only.example.test");
    let hints = addrinfo { ai_family: AF_INET6, ..addrinfo::default() };
    assert_eq!(unsafe { crate::gai::getaddrinfo(v4.as_ptr(), core::ptr::null(), &hints, &mut res) }, EAI_NODATA);
    // gethostbyname and gethostbyaddr
    let h = unsafe { crate::netdb::gethostbyname(n.as_ptr()) };
    let d = dump_hostent(h as *const u8).unwrap();
    assert_eq!((d.0.as_str(), d.1, d.2, d.4), ("web.example.test", vec!["www.example.test".to_string()], AF_INET, vec![vec![192, 0, 2, 1], vec![192, 0, 2, 2]]));
    let ip = [1u8, 2, 3, 4];
    let h = unsafe { crate::netdb::gethostbyaddr(ip.as_ptr() as *const c_void, 4, AF_INET) };
    assert_eq!(dump_hostent(h as *const u8).unwrap().0, "host1234.example.test");
    let mut ip6 = [0u8; 16];
    ip6[0] = 0x20;
    ip6[1] = 0x01;
    ip6[2] = 0x0d;
    ip6[3] = 0xb8;
    ip6[15] = 1;
    let h = unsafe { crate::netdb::gethostbyaddr(ip6.as_ptr() as *const c_void, 16, AF_INET6) };
    assert_eq!(dump_hostent(h as *const u8).unwrap().0, "six.example.test");
    // getnameinfo resolves through the same server
    let (ss, len) = crate::rustapi::SockAddr::v4([1, 2, 3, 4], 80).to_raw();
    let mut host = [0 as c_char; 256];
    assert_eq!(unsafe { crate::gai::getnameinfo(&ss as *const _ as *const sockaddr, len, host.as_mut_ptr(), 256, core::ptr::null_mut(), 0, NI_NAMEREQD) }, 0);
    assert_eq!(unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().unwrap(), "host1234.example.test");
    let (ss, len) = crate::rustapi::SockAddr::v4([9, 9, 9, 9], 80).to_raw();
    assert_eq!(unsafe { crate::gai::getnameinfo(&ss as *const _ as *const sockaddr, len, host.as_mut_ptr(), 256, core::ptr::null_mut(), 0, NI_NAMEREQD) }, EAI_NONAME);
    assert_eq!(unsafe { crate::gai::getnameinfo(&ss as *const _ as *const sockaddr, len, host.as_mut_ptr(), 256, core::ptr::null_mut(), 0, 0) }, 0);
    assert_eq!(unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().unwrap(), "9.9.9.9");
    // a dead server: EAI_AGAIN
    let dead = Fake::start(|_, _| vec![Reply::Drop]);
    let mut c = cfg_for(&dead);
    c.timeout_ms = 100;
    c.attempts = 1;
    c.options |= dns::RES_NORELOAD;
    dns::set_default_config(c);
    assert_eq!(unsafe { crate::gai::getaddrinfo(n.as_ptr(), core::ptr::null(), core::ptr::null(), &mut res) }, EAI_AGAIN);
}

#[test]
fn files_before_dns_and_files_hit_skips_dns() {
    let _l = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let _g = EtcGuard::with_files(&[("nsswitch.conf", "hosts: files dns\n"), ("hosts", "10.9.8.7 myserver.local ms\n::1 ip6host\n")]);
    let mut c = cfg_for(&f);
    c.options |= dns::RES_NORELOAD;
    dns::set_default_config(c);
    let mut hd = HostData::new();
    crate::netdb::lookup_name(b"ms", AF_INET, false, &mut hd).unwrap();
    assert_eq!(&hd.addrs[0].bytes[..4], &[10, 9, 8, 7]);
    assert_eq!(hd.canon.as_bytes(), b"myserver.local");
    assert!(f.seen().is_empty(), "a hit in files must not ask DNS");
    let mut hd = HostData::new();
    crate::netdb::lookup_name(b"v4only.example.test", AF_INET, false, &mut hd).unwrap();
    assert_eq!(f.seen().len(), 1);
    // files miss then dns miss
    let mut hd = HostData::new();
    assert_eq!(crate::netdb::lookup_name(b"nowhere", AF_INET, false, &mut hd), Err(HOST_NOT_FOUND));
}

#[test]
fn res_state_functions() {
    let _l = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(zone);
    let _g = EtcGuard::with_files(&[("resolv.conf", "nameserver 127.0.0.1\nsearch example.test\n")]);
    let mut st = crate::resolv::ResState::zero();
    assert_eq!(unsafe { crate::resolv::__res_ninit(&mut st) }, 0);
    assert_eq!(st.nscount, 1);
    assert!(st.options & dns::RES_INIT as u64 != 0);
    assert_eq!(unsafe { CStr::from_ptr(st.dnsrch[0]) }.to_str().unwrap(), "example.test");
    // point it at the fake server and shorten the timeouts
    st.nsaddr_list[0].sin_port = f.port.to_be();
    st.retrans = 1;
    st.retry = 1;
    let mut ans = [0u8; 1024];
    let n = cs("v4only");
    let r = unsafe { crate::resolv::res_nsearch(&mut st, n.as_ptr(), 1, 1, ans.as_mut_ptr(), 1024) };
    assert!(r > 12, "res_nsearch returned {r}");
    assert_eq!(f.seen().iter().map(|s| s.name.clone()).collect::<Vec<_>>(), ["v4only.example.test"]);
    let h = wire::Header::parse(&ans[..r as usize]).unwrap();
    assert_eq!((h.rcode(), h.ancount), (0, 1));
    // res_nquery asks the name as given
    let x = cs("nosuch.example.test");
    assert_eq!(unsafe { crate::resolv::res_nquery(&mut st, x.as_ptr(), 1, 1, ans.as_mut_ptr(), 1024) }, -1);
    assert_eq!(st.res_h_errno, HOST_NOT_FOUND);
    // res_nquerydomain joins name and domain
    let dm = cs("example.test");
    let vn = cs("v4only");
    let r = unsafe { crate::resolv::res_nquerydomain(&mut st, vn.as_ptr(), dm.as_ptr(), 1, 1, ans.as_mut_ptr(), 1024) };
    assert!(r > 12);
    // an answer buffer that is too small: the answer is cut to fit
    let r = unsafe { crate::resolv::res_nquery(&mut st, cs("v4only.example.test").as_ptr(), 1, 1, ans.as_mut_ptr(), 20) };
    assert_eq!(r, 20);
    // res_nmkquery output equals the host's, except for the id
    let mut mine = [0u8; 100];
    let mut theirs = [0u8; 100];
    let dn = cs("www.example.com");
    let ra = unsafe { crate::resolv::res_nmkquery(&mut st, 0, dn.as_ptr(), 1, 28, core::ptr::null(), 0, core::ptr::null(), mine.as_mut_ptr(), 100) };
    unsafe extern "C" {
        fn res_mkquery(op: c_int, dname: *const c_char, class: c_int, ty: c_int, data: *const u8, datalen: c_int, newrr: *const u8, buf: *mut u8, buflen: c_int) -> c_int;
    }
    let rb = unsafe { res_mkquery(0, dn.as_ptr(), 1, 28, core::ptr::null(), 0, core::ptr::null(), theirs.as_mut_ptr(), 100) };
    assert_eq!(ra, rb);
    assert_eq!(mine[4..ra as usize], theirs[4..ra as usize]);
    assert_eq!(mine[2] & 0xfe, theirs[2] & 0xfe);
    // res_nsend with a hand-made message
    let mut q = [0u8; 600];
    let ql = wire::build_query(0x4242, b"v4only.example.test", 1, 1, true, None, &mut q).unwrap();
    let r = unsafe { crate::resolv::res_nsend(&mut st, q.as_ptr(), ql as c_int, ans.as_mut_ptr(), 1024) };
    assert!(r > 12);
    assert_eq!(wire::get16(&ans, 0), Some(0x4242));
    unsafe { crate::resolv::__res_nclose(&mut st) };
}

/// A TXT record of `len` zero bytes (one character string per 255 bytes), to make an answer large.
fn big_txt(owner: &'static str, len: usize) -> Rec {
    let mut rdata = Vec::new();
    let mut left = len;
    while left > 0 {
        let c = left.min(255);
        rdata.push(c as u8);
        rdata.extend(std::iter::repeat_n(0u8, c));
        left -= c;
    }
    Rec { owner, ty: wire::T_TXT, rdata }
}

#[test]
fn answers_over_4k_are_received_whole() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| {
        let many = |n: usize, owner: &'static str| -> Vec<Rec> { (0..n).map(|i| a(owner, [192, 0, (i >> 8) as u8, i as u8])).collect() };
        match s.name.as_str() {
            // over TCP only: a 50000-byte TXT record in front of 200 addresses (about 57 KiB; the fake server does not compress names)
            "tcp.example.test" if !s.tcp => vec![Reply::Raw(response(q, wire::NOERROR, true, &[]))],
            "tcp.example.test" => {
                let mut recs = vec![big_txt("tcp.example.test", 50000)];
                recs.extend(many(200, "tcp.example.test"));
                vec![Reply::Raw(response(q, wire::NOERROR, false, &recs))]
            }
            // over UDP: 400 addresses in one datagram (about 6.4 KiB)
            "udp.example.test" => vec![Reply::Raw(response(q, wire::NOERROR, false, &many(400, "udp.example.test")))],
            _ => zone(s, q),
        }
    });
    let cfg = cfg_for(&f);
    let hd = lookup(&cfg, "tcp.example.test", AF_INET).unwrap();
    assert_eq!(hd.n, 200);
    let hd = lookup(&cfg, "udp.example.test", AF_INET).unwrap();
    assert_eq!(hd.n, 400);
    assert_eq!(hd.addrs[399].bytes[..4], [192, 0, 1, 143]);
    // a caller's buffer (res_nquery) does not grow: over TCP the answer is cut to it, marked truncated and its whole length
    // returned (as glibc does), over UDP the datagram is cut to it
    let mut small = [0u8; 4096];
    let n = dns::query(&cfg, b"tcp.example.test", wire::C_IN, wire::T_A, &mut small).unwrap();
    assert!(n > 50000, "{n}");
    assert_ne!(small[2] & 0x02, 0);
    let n = dns::query(&cfg, b"udp.example.test", wire::C_IN, wire::T_A, &mut small).unwrap();
    assert_eq!(n, 4096);
}

/// A pair search for `name` with the thread's switches in `flags`: the addresses of both replies, in reply order.
fn pair(cfg: &Config, name: &str, flags: &mut u32) -> Result<Vec<Vec<u8>>, dns::HErr> {
    let (mut f1, mut f2) = ([0u8; 4096], [0u8; 4096]);
    let (mut a1, mut a2) = (dns::Answer::growable(&mut f1), dns::Answer::growable(&mut f2));
    let (n1, n2) = dns::search_pair(cfg, name.as_bytes(), &mut a1, &mut a2, flags)?;
    let mut out = vec![];
    for p in [a1.kept(n1), a2.kept(n2)] {
        if p.len() < wire::HFIXEDSZ {
            continue;
        }
        let mut rd = crate::nssdns::RrReader::new(p).unwrap();
        for _ in 0..rd.ancount {
            let rr = rd.next_rr().unwrap();
            if rr.rtype == wire::T_A || rr.rtype == wire::T_AAAA {
                out.push(p[rr.rdata..rr.rdata + rr.rdlen].to_vec());
            }
        }
    }
    Ok(out)
}

fn dual(s: &Seen, q: &[u8], v4: [u8; 4], v6: &str) -> Vec<Reply> {
    let rec = if s.qtype == wire::T_A { a("dual.example.test", v4) } else { aaaa("dual.example.test", v6) };
    let rec = Rec { owner: Box::leak(s.name.clone().into_boxed_str()), ..rec };
    vec![Reply::Raw(response(q, wire::NOERROR, false, &[rec]))]
}

#[test]
fn a_and_aaaa_go_out_as_one_pair() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = Fake::start(|s, q| dual(s, q, [10, 0, 0, 1], "2001:db8::1"));
    let mut cfg = cfg_for(&f);
    cfg.timeout_ms = 2000;
    let mut flags = 0;
    let t0 = Instant::now();
    let got = pair(&cfg, "dual.example.test", &mut flags).unwrap();
    assert!(t0.elapsed() < Duration::from_millis(1000));
    assert_eq!(got, [vec![10, 0, 0, 1], "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()]);
    assert_eq!(f.seen().iter().map(|s| (s.qtype, s.tcp)).collect::<Vec<_>>(), [(wire::T_A, false), (wire::T_AAAA, false)]);
    assert_eq!(flags, 0);
}

#[test]
fn a_server_that_answers_one_query_of_two_gets_them_one_at_a_time() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // AAAA queries are never answered
    let f = Fake::start(|s, q| if s.qtype == wire::T_AAAA { vec![Reply::Drop] } else { dual(s, q, [10, 0, 0, 1], "::1") });
    let mut cfg = cfg_for(&f);
    cfg.timeout_ms = 100;
    cfg.attempts = 1;
    let mut flags = 0;
    // both at once, then one at a time, then one at a time on a fresh socket; the A reply is used
    let got = pair(&cfg, "dual.example.test", &mut flags).unwrap();
    assert_eq!(got, [vec![10, 0, 0, 1]]);
    assert_eq!(flags, dns::RES_F_SNGLKUP | dns::RES_F_SNGLKUPREOP);
    assert_eq!(f.seen().len(), 6);
    // the thread's flags stay: the next lookup asks one at a time from the start and waits once
    f.log.lock().unwrap().clear();
    let t0 = Instant::now();
    let got = pair(&cfg, "dual.example.test", &mut flags).unwrap();
    assert_eq!(got, [vec![10, 0, 0, 1]]);
    assert!(t0.elapsed() < Duration::from_millis(300), "{:?}", t0.elapsed());
    assert_eq!(f.seen().iter().map(|s| s.qtype).collect::<Vec<_>>(), [wire::T_A, wire::T_AAAA]);
}

#[test]
fn an_error_for_one_query_of_the_pair_keeps_the_other_reply() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // AAAA gets a bare SERVFAIL header (no question), as some resolvers send
    let bare = |q: &[u8]| {
        let mut m = q[..12].to_vec();
        m[2] = 0x81;
        m[3] = 0x80 | wire::SERVFAIL;
        m[4..12].fill(0);
        m
    };
    let first = Fake::start(move |s, q| if s.qtype == wire::T_AAAA { vec![Reply::Raw(bare(q))] } else { dual(s, q, [10, 0, 0, 1], "::1") });
    let second = Fake::start(|s, q| dual(s, q, [10, 0, 0, 2], "2001:db8::2"));
    let mut cfg = Config::with_servers(&[first.server(), second.server()]);
    cfg.timeout_ms = 2000;
    let mut flags = 0;
    let t0 = Instant::now();
    assert_eq!(pair(&cfg, "dual.example.test", &mut flags).unwrap(), [vec![10, 0, 0, 1]]);
    assert!(t0.elapsed() < Duration::from_millis(1000));
    assert!(second.seen().is_empty());
    // RES_STRICTERR: the next server is asked, and both replies come from it
    cfg.options |= dns::RES_STRICTERR;
    let got = pair(&cfg, "dual.example.test", &mut flags).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0], [10, 0, 0, 2]);
}

#[test]
fn a_tcp_pair_that_breaks_is_asked_again_whole_at_the_next_server() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // over UDP everything is truncated; over TCP the first server answers A and closes the connection on AAAA
    let tc = |q: &[u8]| vec![Reply::Raw(response(q, wire::NOERROR, true, &[]))];
    let first = Fake::start(move |s, q| match (s.tcp, s.qtype) {
        (false, _) => tc(q),
        (true, wire::T_AAAA) => vec![Reply::Close],
        _ => dual(s, q, [10, 0, 0, 1], "::1"),
    });
    let second = Fake::start(move |s, q| if s.tcp { dual(s, q, [10, 0, 0, 2], "2001:db8::2") } else { tc(q) });
    let mut cfg = Config::with_servers(&[first.server(), second.server()]);
    cfg.timeout_ms = 2000;
    let mut flags = 0;
    let got = pair(&cfg, "dual.example.test", &mut flags).unwrap();
    assert_eq!(got, [vec![10, 0, 0, 2], "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()]);
    // the second server was asked over TCP straight away (TCP stays on for the rest of the send)
    assert!(second.seen().iter().all(|s| s.tcp));
}

#[test]
fn server_timeouts_follow_glibc() {
    let s = |t: i64, n: usize, ns: usize| {
        let mut c = Config::with_servers(&[Server::v4([127, 0, 0, 1], 53); 3][..n]);
        c.timeout_ms = t;
        dns::server_ms(&c, ns)
    };
    // retrans << ns, divided by the number of servers after the first, at least one second
    assert_eq!((s(5000, 3, 0), s(5000, 3, 1), s(5000, 3, 2)), (5000, 3000, 6000));
    assert_eq!((s(1000, 3, 1), s(1000, 2, 1), s(2000, 1, 0)), (1000, 1000, 2000));
    // timeout:0 and negative timeouts (glibc keeps them as an int): one second per try
    assert_eq!((s(0, 1, 0), s(-1000, 3, 1), s(-5000, 1, 0), s(-30000, 2, 2)), (1000, 1000, 1000, 1000));
}
