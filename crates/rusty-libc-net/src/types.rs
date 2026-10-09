use core::ffi::{c_char, c_int, c_uint, c_void};

pub type socklen_t = u32;
pub type sa_family_t = u16;
pub type in_port_t = u16;
pub type in_addr_t = u32;
#[allow(non_camel_case_types)]
pub type ssize_t = isize;

pub const AF_UNSPEC: c_int = 0;
pub const AF_UNIX: c_int = 1;
pub const AF_LOCAL: c_int = 1;
pub const AF_INET: c_int = 2;
pub const AF_NETLINK: c_int = 16;
pub const AF_PACKET: c_int = 17;
pub const AF_INET6: c_int = 10;
pub const PF_UNSPEC: c_int = 0;
pub const PF_INET: c_int = 2;
pub const PF_INET6: c_int = 10;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_SEQPACKET: c_int = 5;
pub const SOCK_NONBLOCK: c_int = 0o4000;
pub const SOCK_CLOEXEC: c_int = 0o2000000;

pub const SOL_SOCKET: c_int = 1;
pub const SO_REUSEADDR: c_int = 2;
pub const SO_TYPE: c_int = 3;
pub const SO_ERROR: c_int = 4;
pub const SO_RCVBUF: c_int = 8;
pub const SO_SNDBUF: c_int = 7;
pub const SO_KEEPALIVE: c_int = 9;
pub const SO_RCVTIMEO: c_int = 20;
pub const SO_SNDTIMEO: c_int = 21;
pub const SO_PASSCRED: c_int = 16;
pub const SO_PEERCRED: c_int = 17;

pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPPROTO_ICMPV6: c_int = 58;
pub const IPPROTO_RAW: c_int = 255;
pub const IPV6_V6ONLY: c_int = 26;
pub const TCP_NODELAY: c_int = 1;

pub const MSG_OOB: c_int = 1;
pub const MSG_PEEK: c_int = 2;
pub const MSG_DONTWAIT: c_int = 0x40;
pub const MSG_TRUNC: c_int = 0x20;
pub const MSG_CTRUNC: c_int = 8;
pub const MSG_NOSIGNAL: c_int = 0x4000;
pub const MSG_WAITALL: c_int = 0x100;
pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;

pub const SHUT_RD: c_int = 0;
pub const SHUT_WR: c_int = 1;
pub const SHUT_RDWR: c_int = 2;

pub const SCM_RIGHTS: c_int = 1;
pub const SCM_CREDENTIALS: c_int = 2;

pub const INADDR_ANY: u32 = 0;
pub const INADDR_LOOPBACK: u32 = 0x7f00_0001;
pub const INADDR_BROADCAST: u32 = 0xffff_ffff;
pub const INADDR_NONE: u32 = 0xffff_ffff;

pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;

pub const AI_PASSIVE: c_int = 1;
pub const AI_CANONNAME: c_int = 2;
pub const AI_NUMERICHOST: c_int = 4;
pub const AI_V4MAPPED: c_int = 8;
pub const AI_ALL: c_int = 0x10;
pub const AI_ADDRCONFIG: c_int = 0x20;
pub const AI_IDN: c_int = 0x40;
pub const AI_CANONIDN: c_int = 0x80;
pub const AI_NUMERICSERV: c_int = 0x400;

pub const NI_NUMERICHOST: c_int = 1;
pub const NI_NUMERICSERV: c_int = 2;
pub const NI_NOFQDN: c_int = 4;
pub const NI_NAMEREQD: c_int = 8;
pub const NI_DGRAM: c_int = 16;
pub const NI_IDN: c_int = 32;
pub const NI_MAXHOST: usize = 1025;
pub const NI_MAXSERV: usize = 32;

pub const EAI_BADFLAGS: c_int = -1;
pub const EAI_NONAME: c_int = -2;
pub const EAI_AGAIN: c_int = -3;
pub const EAI_FAIL: c_int = -4;
pub const EAI_NODATA: c_int = -5;
pub const EAI_FAMILY: c_int = -6;
pub const EAI_SOCKTYPE: c_int = -7;
pub const EAI_SERVICE: c_int = -8;
pub const EAI_ADDRFAMILY: c_int = -9;
pub const EAI_MEMORY: c_int = -10;
pub const EAI_SYSTEM: c_int = -11;
pub const EAI_OVERFLOW: c_int = -12;
pub const EAI_INPROGRESS: c_int = -100;
pub const EAI_CANCELED: c_int = -101;
pub const EAI_NOTCANCELED: c_int = -102;
pub const EAI_ALLDONE: c_int = -103;
pub const EAI_INTR: c_int = -104;
pub const EAI_IDN_ENCODE: c_int = -105;

pub const NETDB_INTERNAL: c_int = -1;
pub const NETDB_SUCCESS: c_int = 0;
pub const HOST_NOT_FOUND: c_int = 1;
pub const TRY_AGAIN: c_int = 2;
pub const NO_RECOVERY: c_int = 3;
pub const NO_DATA: c_int = 4;
pub const NO_ADDRESS: c_int = 4;

pub const EINTR: i32 = 4;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const EINVAL: i32 = 22;
pub const EBUSY: i32 = 16;
pub const ENOSPC: i32 = 28;
pub const ERANGE: i32 = 34;
pub const EAFNOSUPPORT: i32 = 97;
pub const ETIMEDOUT: i32 = 110;
pub const EINPROGRESS: i32 = 115;
pub const ECONNREFUSED: i32 = 111;
pub const EMSGSIZE: i32 = 90;
pub const EBADF: i32 = 9;
pub const ENOTSOCK: i32 = 88;
pub const ENODEV: i32 = 19;
pub const ENXIO: i32 = 6;
pub const EPERM: i32 = 1;
pub const EACCES: i32 = 13;
pub const EADDRINUSE: i32 = 98;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [u8; 108],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [u8; 118],
    pub __ss_align: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sockaddr_nl {
    pub nl_family: sa_family_t,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct sockaddr_ll {
    pub sll_family: u16,
    pub sll_protocol: u16,
    pub sll_ifindex: c_int,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

impl Default for sockaddr_un {
    fn default() -> Self {
        sockaddr_un { sun_family: 0, sun_path: [0; 108] }
    }
}
impl Default for sockaddr_storage {
    fn default() -> Self {
        sockaddr_storage { ss_family: 0, __ss_padding: [0; 118], __ss_align: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct cmsghdr {
    pub cmsg_len: usize,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct mmsghdr {
    pub msg_hdr: msghdr,
    pub msg_len: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct linger {
    pub l_onoff: c_int,
    pub l_linger: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct hostent {
    pub h_name: *mut c_char,
    pub h_aliases: *mut *mut c_char,
    pub h_addrtype: c_int,
    pub h_length: c_int,
    pub h_addr_list: *mut *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct servent {
    pub s_name: *mut c_char,
    pub s_aliases: *mut *mut c_char,
    pub s_port: c_int,
    pub s_proto: *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct protoent {
    pub p_name: *mut c_char,
    pub p_aliases: *mut *mut c_char,
    pub p_proto: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct netent {
    pub n_name: *mut c_char,
    pub n_aliases: *mut *mut c_char,
    pub n_addrtype: c_int,
    pub n_net: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct rpcent {
    pub r_name: *mut c_char,
    pub r_aliases: *mut *mut c_char,
    pub r_number: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct aliasent {
    pub alias_name: *mut c_char,
    pub alias_members_len: usize,
    pub alias_members: *mut *mut c_char,
    pub alias_local: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct addrinfo {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut c_char,
    pub ai_next: *mut addrinfo,
}

impl Default for addrinfo {
    fn default() -> Self {
        addrinfo {
            ai_flags: 0,
            ai_family: 0,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: core::ptr::null_mut(),
            ai_canonname: core::ptr::null_mut(),
            ai_next: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct if_nameindex {
    pub if_index: c_uint,
    pub if_name: *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ifa_ifu {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: ifa_ifu,
    pub ifa_data: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ether_addr {
    pub ether_addr_octet: [u8; 6],
}

pub const NS_PACKETSZ: usize = 512;
