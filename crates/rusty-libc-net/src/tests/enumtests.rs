//! Enumeration (setXXent / getXXent_r / endXXent): every entry comes back once, in order, whatever the buffer size (an
//! entry that does not fit is delivered again once the buffer is big enough, not dropped), a restart by set starts over,
//! and the plain getXXent leaves errno alone at the end. The differential checks against glibc are in tests/dyn
//! (nss_enum.c, nss_enum_mod.c); the module and action-list engine has its own unit tests in rusty-libc-core.
use super::*;
use crate::{netdb, types::*};
use core::ptr::null_mut;

const SERVICES: &str = "alpha 1001/tcp a1 a2\nalpha 1001/udp\n# comment\n\nbeta 1002/tcp\ngamma-with-a-long-name 1003/tcp long-alias-one long-alias-two long-alias-three\n";
const PROTOCOLS: &str = "p0 200 P0 pa pb\np1 201 P1\np2 202\n";
const RPC: &str = "r0 300000 r0a\nr1 300001\n";
const NETWORKS: &str = "n0 10.0.0.0 n0a\nn1 172.16.0.0\n";
const HOSTS: &str = "192.0.2.1 h1 h1a h1b\n192.0.2.2 h2\n";
const ALIASES: &str = "first: a, b,\n  c\nsecond: d\n";

fn names<T>(next: impl FnMut(*mut T, *mut c_char, usize, *mut *mut T) -> c_int, show: impl Fn(*const T) -> String) -> Vec<String> {
    names_from(1, next, show)
}

/// Like `names`, starting with a buffer of `cap0` bytes (the aliases file is read like glibc's: a buffer that is too small
/// loses what was read, so it has to be big enough from the start).
fn names_from<T>(cap0: usize, mut next: impl FnMut(*mut T, *mut c_char, usize, *mut *mut T) -> c_int, show: impl Fn(*const T) -> String) -> Vec<String> {
    let mut out = Vec::new();
    let mut res: T = unsafe { core::mem::zeroed() };
    let mut cap = cap0;
    let mut buf = vec![0u8; 8192];
    loop {
        let mut p: *mut T = null_mut();
        let rc = next(&mut res, buf.as_mut_ptr() as *mut c_char, cap, &mut p);
        if rc == ERANGE {
            cap += 1; // every size from 1 byte up: the entry must not be lost
            assert!(cap <= buf.len());
            continue;
        }
        if rc != 0 || p.is_null() {
            return out;
        }
        out.push(show(p));
        cap = cap0;
    }
}

fn cs(p: *const c_char) -> String {
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

#[test]
fn enumerations_return_every_entry_with_tiny_buffers_and_restart() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::with_files(&[("services", SERVICES), ("protocols", PROTOCOLS), ("rpc", RPC), ("networks", NETWORKS), ("hosts", HOSTS), ("aliases", ALIASES)]);
    unsafe {
        netdb::setservent(0);
        let v = names::<servent>(|r, b, n, o| netdb::getservent_r(r, b, n, o), |p| format!("{} {}", cs((*p).s_name), (*p).s_port));
        netdb::endservent();
        assert_eq!(v.len(), 4, "{v:?}");
        assert!(v[3].starts_with("gamma-with-a-long-name"));
        // a restart by set starts over, a plain getservent after end opens it again
        netdb::setservent(1);
        let first = cs((*netdb::getservent()).s_name);
        netdb::setservent(1);
        assert_eq!(cs((*netdb::getservent()).s_name), first);
        netdb::endservent();
        assert_eq!(cs((*netdb::getservent()).s_name), first);
        netdb::endservent();

        netdb::setprotoent(0);
        let v = names::<protoent>(|r, b, n, o| netdb::getprotoent_r(r, b, n, o), |p| format!("{} {}", cs((*p).p_name), (*p).p_proto));
        netdb::endprotoent();
        assert_eq!(v, ["p0 200", "p1 201", "p2 202"]);

        netdb::setrpcent(0);
        let v = names::<rpcent>(|r, b, n, o| netdb::getrpcent_r(r, b, n, o), |p| cs((*p).r_name));
        netdb::endrpcent();
        assert_eq!(v, ["r0", "r1"]);

        let mut h = 0;
        netdb::setnetent(0);
        let v = names::<netent>(|r, b, n, o| netdb::getnetent_r(r, b, n, o, &mut h), |p| cs((*p).n_name));
        netdb::endnetent();
        assert_eq!(v, ["n0", "n1"]);

        netdb::sethostent(0);
        let v = names::<hostent>(|r, b, n, o| netdb::gethostent_r(r, b, n, o, &mut h), |p| cs((*p).h_name));
        netdb::endhostent();
        assert_eq!(v, ["h1", "h2"]);

        netdb::setaliasent();
        let v = names_from::<aliasent>(512, |r, b, n, o| netdb::getaliasent_r(r, b, n, o), |p| format!("{} {}", cs((*p).alias_name), (*p).alias_members_len));
        netdb::endaliasent();
        assert_eq!(v, ["first 3", "second 1"]);
    }
}

#[test]
fn plain_getent_leaves_errno_alone_at_the_end() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::with_files(&[("protocols", PROTOCOLS)]);
    {
        netdb::setprotoent(0);
        rusty_libc_core::errno::set(0);
        let mut n = 0;
        while !netdb::getprotoent().is_null() {
            n += 1;
        }
        assert_eq!(n, 3);
        // glibc's __nss_getent does not set errno when the enumeration ends
        assert_eq!(rusty_libc_core::errno::get(), 0);
        netdb::endprotoent();
    }
}

#[test]
fn an_empty_source_list_enumerates_nothing() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    {
        // `rpc:` with no source in nsswitch.conf: no source at all
        let _etc = EtcGuard::with_files(&[("rpc", RPC), ("nsswitch.conf", "rpc:\n")]);
        {
            netdb::setrpcent(0);
            assert!(netdb::getrpcent().is_null());
            netdb::endrpcent();
        }
    }
    let _etc = EtcGuard::with_files(&[("rpc", RPC), ("nsswitch.conf", "rpc: files\n")]);
    {
        netdb::setrpcent(0);
        assert!(!netdb::getrpcent().is_null());
        netdb::endrpcent();
    }
}

/// glibc parses each line in place, so the smallest buffer an entry needs is fixed by its line: the alias vector goes after the
/// line (and its newline and terminator), 8-aligned, with room for the aliases, a null and one spare. The numbers below are
/// worked out by hand from nss/nss_files/files-parse.c and checked against glibc by tests/dyn/c/nss_erange.c.
#[test]
fn the_smallest_buffer_is_the_one_glibc_needs() {
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::with_files(&[("protocols", PROTOCOLS), ("rpc", RPC)]);
    // 8-aligned storage: the thresholds depend on the address of the buffer
    let mut backing = vec![0u64; 64];
    let buf = backing.as_mut_ptr() as *mut c_char;
    unsafe {
        let mut mins = Vec::new();
        netdb::setprotoent(0);
        let mut res: protoent = core::mem::zeroed();
        for _ in 0..3 {
            let mut cap = 0usize;
            loop {
                let mut out: *mut protoent = null_mut();
                let rc = netdb::getprotoent_r(&mut res, buf, cap, &mut out);
                if rc == ERANGE {
                    cap += 1;
                    continue;
                }
                assert_eq!(rc, 0);
                break;
            }
            mins.push(cap);
        }
        netdb::endprotoent();
        // "p0 200 P0 pa pb\n": 16 bytes, 3 aliases: list at align8(17) = 24, 24 + 8 * 5; "p1 201 P1\n": 10 bytes, 1 alias: 16 + 24;
        // "p2 202\n": 7 bytes, none: 8 + 16
        assert_eq!(mins, [64, 40, 24]);
        // rpc: "r0 300000 r0a\n" 14 bytes, 1 alias: 16 + 24; "r1 300001\n" 10 bytes, none: 16 + 16
        let mut mins = Vec::new();
        netdb::setrpcent(0);
        let mut res: rpcent = core::mem::zeroed();
        for _ in 0..2 {
            let mut cap = 0usize;
            loop {
                let mut out: *mut rpcent = null_mut();
                let rc = netdb::getrpcent_r(&mut res, buf, cap, &mut out);
                if rc == ERANGE {
                    cap += 1;
                    continue;
                }
                assert_eq!(rc, 0);
                break;
            }
            mins.push(cap);
        }
        netdb::endrpcent();
        assert_eq!(mins, [40, 32]);
        // a lookup that reads every line needs the room of the most demanding one
        let mut out: *mut rpcent = null_mut();
        assert_eq!(netdb::getrpcbyname_r(c"nosuch".as_ptr(), &mut res, buf, 39, &mut out), ERANGE);
        assert_eq!(netdb::getrpcbyname_r(c"nosuch".as_ptr(), &mut res, buf, 40, &mut out), 0);
        assert!(out.is_null());
    }
}

/// glibc's aliases thresholds (tests/dyn nss-erange): each entry is read with buffers of 0, 1, 2 ... bytes until it fits
/// (a refused buffer loses what was read, as in glibc), at five buffer alignments. The numbers are glibc 2.43's for this
/// file (Fedora's /etc/aliases). glibc writes the member pointer array up to 7 bytes past the buffer; ours never does (FIXLIST
/// #87), so each of our thresholds is glibc's or up to 8 bytes more, and every entry is still read.
#[test]
fn aliases_erange_thresholds_match_glibc() {
    use crate::types::aliasent;
    let _lock = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _etc = EtcGuard::with_files(&[("aliases", include_str!("aliases.fixture"))]);
    let mut store = vec![0u8; 8200];
    for off in [0usize, 1, 3, 4, 7] {
        let buf = unsafe { store.as_mut_ptr().add(off) } as *mut core::ffi::c_char;
        netdb::setaliasent();
        let mut mins = Vec::new();
        let end = loop {
            let mut res = aliasent { alias_name: core::ptr::null_mut(), alias_members_len: 0, alias_members: core::ptr::null_mut(), alias_local: 0 };
            let mut rv: *mut aliasent = core::ptr::null_mut();
            let mut bl = 0usize;
            let rc = loop {
                let rc = unsafe { netdb::getaliasent_r(&mut res, buf, bl, &mut rv) };
                if rc != libc::ERANGE || bl >= 4096 {
                    break rc;
                }
                bl += 1;
            };
            if rc != 0 || rv.is_null() {
                break rc;
            }
            mins.push(bl);
        };
        netdb::endaliasent();
        let glibc = [29usize, 17, 16, 24, 24, 24, 24];
        assert_eq!((mins.len(), end), (glibc.len(), libc::ENOENT), "buffer offset {off}");
        for (ours, theirs) in mins.iter().zip(glibc) {
            assert!((theirs..=theirs + 8).contains(ours), "buffer offset {off}: {mins:?} against glibc's {glibc:?}");
        }
    }
}
