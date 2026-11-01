//! Host tests: our functions against the host's glibc, plus a fake DNS server for the resolver.
#![allow(clippy::missing_safety_doc, clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};

pub(crate) use hosttests::{dump_hostent, dump_protoent, dump_servent, servent_zero};
mod dnstest;
mod enumtests;
mod gaitests;
mod hosttests;
mod nssdnsabitest;
mod nssdnstest;
mod netgrptests;
mod nstests;
mod rcmdtests;
mod resdebugtests;
mod socktests;

/// The host's own versions of what we implement (they link against the host libc: our functions
/// are not exported in test builds).
pub(crate) mod host {
    use super::*;
    unsafe extern "C" {
        pub fn inet_aton(cp: *const c_char, addr: *mut u32) -> c_int;
        pub fn inet_addr(cp: *const c_char) -> u32;
        pub fn inet_network(cp: *const c_char) -> u32;
        pub fn inet_ntoa(a: u32) -> *const c_char;
        pub fn inet_makeaddr(net: u32, host: u32) -> u32;
        pub fn inet_lnaof(a: u32) -> u32;
        pub fn inet_netof(a: u32) -> u32;
        pub fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
        pub fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
        pub fn inet_nsap_addr(ascii: *const c_char, binary: *mut u8, maxlen: c_int) -> u32;
        pub fn inet_nsap_ntoa(binlen: c_int, binary: *const u8, ascii: *mut c_char) -> *const c_char;
        pub fn gai_strerror(c: c_int) -> *const c_char;
        pub fn hstrerror(c: c_int) -> *const c_char;
        pub fn ether_aton_r(asc: *const c_char, addr: *mut u8) -> *mut u8;
        pub fn ether_ntoa_r(addr: *const u8, buf: *mut c_char) -> *const c_char;
        pub fn ether_line(line: *const c_char, addr: *mut u8, host: *mut c_char) -> c_int;
        pub fn htons(x: u16) -> u16;
        pub fn ntohs(x: u16) -> u16;
        pub fn htonl(x: u32) -> u32;
        pub fn ntohl(x: u32) -> u32;
        pub fn getservbyname_r(name: *const c_char, proto: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn getservbyport_r(port: c_int, proto: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn getprotobyname_r(name: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn getprotobynumber_r(n: c_int, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn getnetbyname_r(name: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8, h: *mut c_int) -> c_int;
        pub fn getrpcbyname_r(name: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn getrpcbynumber_r(n: c_int, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn gethostbyname_r(name: *const c_char, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8, h: *mut c_int) -> c_int;
        pub fn gethostbyname2_r(name: *const c_char, af: c_int, res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8, h: *mut c_int) -> c_int;
        pub fn gethostbyaddr_r(addr: *const c_void, len: u32, af: c_int, res: *mut u8, buf: *mut c_char, blen: usize, result: *mut *mut u8, h: *mut c_int) -> c_int;
        pub fn dn_expand(msg: *const u8, eom: *const u8, src: *const u8, dst: *mut c_char, siz: c_int) -> c_int;
        pub fn dn_comp(src: *const c_char, dst: *mut u8, siz: c_int, dnptrs: *mut *mut u8, last: *mut *mut u8) -> c_int;
        pub fn dn_skipname(p: *const u8, eom: *const u8) -> c_int;
        pub fn ns_name_pton(src: *const c_char, dst: *mut u8, siz: usize) -> c_int;
        pub fn ns_name_ntop(src: *const u8, dst: *mut c_char, siz: usize) -> c_int;
        pub fn res_hnok(dn: *const c_char) -> c_int;
        pub fn res_dnok(dn: *const c_char) -> c_int;
        pub fn res_ownok(dn: *const c_char) -> c_int;
        pub fn res_mailok(dn: *const c_char) -> c_int;
        pub fn inet6_opt_init(b: *mut c_void, l: u32) -> c_int;
        pub fn inet6_opt_append(b: *mut c_void, l: u32, off: c_int, t: u8, len: u32, al: u8, d: *mut *mut c_void) -> c_int;
        pub fn inet6_opt_finish(b: *mut c_void, l: u32, off: c_int) -> c_int;
        pub fn inet6_rth_space(t: c_int, s: c_int) -> u32;
        pub fn setservent(stay: c_int);
        pub fn endservent();
        pub fn getservent_r(res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn setprotoent(stay: c_int);
        pub fn endprotoent();
        pub fn getprotoent_r(res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8) -> c_int;
        pub fn sethostent(stay: c_int);
        pub fn endhostent();
        pub fn gethostent_r(res: *mut u8, buf: *mut c_char, len: usize, result: *mut *mut u8, h: *mut c_int) -> c_int;
        pub fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut u8;
        pub fn getprotobyname(name: *const c_char) -> *mut u8;
        pub fn getprotobynumber(n: c_int) -> *mut u8;
        pub fn gethostbyname(name: *const c_char) -> *mut u8;
        pub fn gethostbyname2(name: *const c_char, af: c_int) -> *mut u8;
        pub fn gethostbyaddr(addr: *const c_void, len: u32, af: c_int) -> *mut u8;
    }
}

pub(crate) fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

pub(crate) fn cstr_opt(p: *const c_char) -> Option<String> {
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
}

pub(crate) struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Points the library at a private directory whose nsswitch.conf says `hosts: files` (so no test ever
/// reaches DNS) with the host's /etc/hosts and /etc/host.conf copied in; restored on drop.
pub(crate) struct EtcGuard {
    dir: std::path::PathBuf,
}

impl EtcGuard {
    pub fn files_only() -> EtcGuard {
        Self::with_files(&[])
    }
    pub fn with_files(extra: &[(&str, &str)]) -> EtcGuard {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("libc-net-etc-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nsswitch.conf"), "hosts: files\nnetworks: files\nservices: files\n").unwrap();
        for f in ["hosts", "host.conf", "services", "protocols", "networks", "rpc", "aliases", "ethers"] {
            if let Ok(b) = std::fs::read(format!("/etc/{f}")) {
                std::fs::write(dir.join(f), b).unwrap();
            }
        }
        for (n, c) in extra {
            std::fs::write(dir.join(n), c).unwrap();
        }
        crate::nss::set_etc_dir(dir.to_str().unwrap().as_bytes());
        crate::dns::reset_default();
        EtcGuard { dir }
    }
}

impl Drop for EtcGuard {
    fn drop(&mut self) {
        crate::nss::set_etc_dir(b"");
        crate::dns::reset_default();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
