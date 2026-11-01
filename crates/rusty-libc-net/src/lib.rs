//! Sockets and name resolution: sys/socket.h, netinet/in.h, arpa/inet.h, netdb.h, ifaddrs.h, net/if.h,
//! netinet/ether.h, resolv.h and the name-server (DNS) client behind them. Written function by function;
//! behaviour oracle is glibc 2.43.
//!
//! Name service switch: only the `files` and `dns` sources exist (see [`nss`]). `/etc/nsswitch.conf` is
//! read for the order; every other source (`myhostname`, `resolve`, `mdns4_minimal`, `systemd`, ...) is
//! skipped, so a system that depends on one of them for a name will not find it here. systemd-resolved's
//! stub listener (127.0.0.53) is plain DNS and works as a `dns` source.
#![cfg_attr(not(test), no_std)]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
// U2 (BRIEF-UNSAFE.md): thin unsafe shell, safe core. Every unsafe block names why it holds and does one unsafe thing. What
// stays unsafe, listed at the top of each module: the C callers' raw pointers converted once per shell (rusty_libc_core::ffi
// and per-module helpers), system calls that pass pointers, plug-in module functions (dlsym'd, transmuted to their C type),
// heap blocks and caller buffers handed back to C (hostent, addrinfo, ifaddrs, netent ...), glibc layouts read by programs
// (_res, ns_msg, ns_rr, struct __netgrent, gaicb), C varargs (warn/warnx) and the stdio calls of the resolver printers.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::too_many_arguments, clippy::type_complexity, clippy::collapsible_if, clippy::needless_range_loop, clippy::if_same_then_else)]
#![allow(clippy::needless_late_init, clippy::result_unit_err, clippy::ptr_eq)]

pub mod types;
pub(crate) mod util;
pub mod sock; // sys/socket.h system calls, cmsg, Rust socket API
pub mod inet; // arpa/inet.h, netinet/in.h functions, in6addr_*, byte order
pub mod b64; // __b64_ntop, __b64_pton (resolver base 64)
pub mod strerr; // gai_strerror, hstrerror, herror
pub mod wire; // DNS wire format: names, headers, records
pub mod dns; // the DNS client (Resolver)
pub mod nssdns_abi; // the nine exported _nss_dns_* functions (GLIBC_PRIVATE) over the parsers
pub mod nssdns; // the nss_dns answer parsers: host, address, canonical name, network (no I/O)
pub mod nss; // /etc/hosts, services, protocols, networks, rpc, aliases, ethers; nsswitch.conf
pub mod hostid; // gethostid (unistd.h; needs the resolver)
pub mod netdb; // gethostby*, getservby*, getprotoby*, getnetby*, getrpcby*, getalias*, *ent
pub mod gai; // getaddrinfo, getnameinfo, freeaddrinfo
pub mod idna; // AI_IDN / AI_CANONIDN / NI_IDN through libidn2.so.0, loaded at run time as glibc does
pub mod ifaddrs; // net/if.h, ifaddrs.h
pub mod resolv; // resolv.h: res_*, dn_*, ns_name_*
pub mod compathost; // res_gethostbyname, res_gethostbyaddr, _gethtent and kin (old resolver host lookups)
pub mod resdebug; // resolver debugging printers and helpers (__p_type, __fp_query, inet_net_*, ...)
pub mod nsparse; // arpa/nameser.h: ns_initparse, ns_parserr, ns_sprintrr, ns_*ttl, ns_samedomain, ...
pub mod ether; // netinet/ether.h
pub mod rustapi; // TcpStream-like Rust API
pub mod misc; // bindresvport, inet6_opt/rth, ...
pub mod inetx; // inet6_option_* (RFC 2292), source filters
pub mod netgrp; // setnetgrent, getnetgrent, innetgr
pub mod nsscompat; // the `compat` source of passwd, group, shadow (glibc's libnss_compat)
pub mod rcmd; // rcmd, rexec, rresvport, ruserok, iruserok
pub mod gai_async; // getaddrinfo_a, gai_suspend, gai_error, gai_cancel

/// One lock for tests that touch global state (resolver configuration, static buffers).
#[cfg(test)]
pub(crate) static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
