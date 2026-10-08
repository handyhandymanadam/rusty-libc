#![allow(non_snake_case)]

mod aio;
mod aliases;
mod alloca;
mod ar;
mod argp;
mod argz;
mod assert;
mod byteswap;
mod cpio;
mod dlfcn;
mod elf;
mod endian;
mod envz;
mod execinfo;
mod features;
mod fenv;
mod fmtmsg;
mod fpu_control;
mod fstab;
mod fts;
mod ftw;
mod getopt;
mod gnu_versions;
mod gshadow;
mod ifaddrs;
mod inttypes;
mod langinfo;
mod libintl;
mod limits;
mod link;
mod locale;
mod math;
mod mcheck;
mod memory;
mod mntent;
mod monetary;
mod mqueue;
mod netdb;
mod nl_types;
mod nss;
mod obstack;
mod paths;
mod printf;
mod pthread;
mod regex;
mod resolv;
mod semaphore;
mod setjmp;
mod sgtty;
mod signal;
mod spawn;
mod stdbit;
mod stdc_predef;
mod stdint;
mod syscall;
mod sysexits;
mod syslog;
mod tar;
mod tgmath;
mod threads;
mod ttyent;
mod ucontext;
mod utmp;
mod utmpx;
mod values;
mod wait;
mod wordexp;
mod arpa_inet;
mod arpa_nameser;
mod arpa_telnet;
mod bits_byteswap;
mod bits_endian;
mod bits_floatn_common;
mod bits_floatn;
mod bits_getopt_posix;
mod bits_hwcap;
mod bits_pthreadtypes;
mod bits_rlibc_cdefs;
mod bits_rlibc_features;
mod bits_sigcontext;
mod bits_sockaddr;
mod bits_types;
mod bits_uintn_identity;
mod bits_waitflags;
mod bits_waitstatus;
mod bits_wordsize;
mod bits_platform_features;
mod bits_platform_x86;
mod bits_types___sigset_t;
mod bits_types___sigval_t;
mod bits_types_clock_t;
mod bits_types_clockid_t;
mod bits_types_locale_t;
mod bits_types_siginfo_t;
mod bits_types_sigset_t;
mod bits_types_stack_t;
mod bits_types_struct_FILE;
mod bits_types_struct_itimerspec;
mod bits_types_struct_sigevent;
mod bits_types_struct_sigstack;
mod bits_types_struct_timespec;
mod bits_types_struct_timeval;
mod bits_types_struct_tm;
mod bits_types_suseconds_t;
mod bits_types_time_t;
mod bits_types_timer_t;
mod gnu_lib_names_64;
mod gnu_lib_names;
mod gnu_libc_version;
mod net_ethernet;
mod net_if;
mod net_if_arp;
mod net_route;
mod netinet_ether;
mod netinet_icmp6;
mod netinet_if_ether;
mod netinet_if_fddi;
mod netinet_igmp;
mod netinet_in;
mod netinet_in_systm;
mod netinet_ip;
mod netinet_ip6;
mod netinet_ip_icmp;
mod netinet_tcp;
mod netinet_udp;
mod netpacket_packet;
mod rpc_auth;
mod rpc_auth_des;
mod rpc_auth_unix;
mod rpc_clnt;
mod rpc_clnt_stat;
mod rpc_des_crypt;
mod rpc_key_prot;
mod rpc_netdb;
mod rpc_pmap_clnt;
mod rpc_pmap_prot;
mod rpc_pmap_rmt;
mod rpc_rpc;
mod rpc_rpc_msg;
mod rpc_svc;
mod rpc_svc_auth;
mod rpc_types;
mod rpc_xdr;
mod sys_cdefs;
mod sys_dir;
mod sys_errno;
mod sys_fcntl;
mod sys_gmon;
mod sys_gmon_out;
mod sys_io;
mod sys_ipc;
mod sys_kd;
mod sys_msg;
mod sys_mtio;
mod sys_param;
mod sys_perm;
mod sys_poll;
mod sys_procfs;
mod sys_profil;
mod sys_queue;
mod sys_sem;
mod sys_shm;
mod sys_signal;
mod sys_single_threaded;
mod sys_socket;
mod sys_syslog;
mod sys_termios;
mod sys_ttychars;
mod sys_ucontext;
mod sys_un;
mod sys_unistd;
mod sys_user;
mod sys_vfs;
mod sys_vlimit;
mod sys_vt;
mod sys_platform_x86;

use crate::model::Header;

pub static ALL: &[&Header] = &[
    &aio::HDR,
    &aliases::HDR,
    &alloca::HDR,
    &ar::HDR,
    &argp::HDR,
    &argz::HDR,
    &assert::HDR,
    &byteswap::HDR,
    &cpio::HDR,
    &dlfcn::HDR,
    &elf::HDR,
    &endian::HDR,
    &envz::HDR,
    &execinfo::HDR,
    &features::HDR,
    &fenv::HDR,
    &fmtmsg::HDR,
    &fpu_control::HDR,
    &fstab::HDR,
    &fts::HDR,
    &ftw::HDR,
    &getopt::HDR,
    &gnu_versions::HDR,
    &gshadow::HDR,
    &ifaddrs::HDR,
    &inttypes::HDR,
    &langinfo::HDR,
    &libintl::HDR,
    &limits::HDR,
    &link::HDR,
    &locale::HDR,
    &math::HDR,
    &mcheck::HDR,
    &memory::HDR,
    &mntent::HDR,
    &monetary::HDR,
    &mqueue::HDR,
    &netdb::HDR,
    &nl_types::HDR,
    &nss::HDR,
    &obstack::HDR,
    &paths::HDR,
    &printf::HDR,
    &pthread::HDR,
    &regex::HDR,
    &resolv::HDR,
    &semaphore::HDR,
    &setjmp::HDR,
    &sgtty::HDR,
    &signal::HDR,
    &spawn::HDR,
    &stdbit::HDR,
    &stdc_predef::HDR,
    &stdint::HDR,
    &syscall::HDR,
    &sysexits::HDR,
    &syslog::HDR,
    &tar::HDR,
    &tgmath::HDR,
    &threads::HDR,
    &ttyent::HDR,
    &ucontext::HDR,
    &utmp::HDR,
    &utmpx::HDR,
    &values::HDR,
    &wait::HDR,
    &wordexp::HDR,
    &arpa_inet::HDR,
    &arpa_nameser::HDR,
    &arpa_telnet::HDR,
    &bits_byteswap::HDR,
    &bits_endian::HDR,
    &bits_floatn_common::HDR,
    &bits_floatn::HDR,
    &bits_getopt_posix::HDR,
    &bits_hwcap::HDR,
    &bits_pthreadtypes::HDR,
    &bits_rlibc_cdefs::HDR,
    &bits_rlibc_features::HDR,
    &bits_sigcontext::HDR,
    &bits_sockaddr::HDR,
    &bits_types::HDR,
    &bits_uintn_identity::HDR,
    &bits_waitflags::HDR,
    &bits_waitstatus::HDR,
    &bits_wordsize::HDR,
    &bits_platform_features::HDR,
    &bits_platform_x86::HDR,
    &bits_types___sigset_t::HDR,
    &bits_types___sigval_t::HDR,
    &bits_types_clock_t::HDR,
    &bits_types_clockid_t::HDR,
    &bits_types_locale_t::HDR,
    &bits_types_siginfo_t::HDR,
    &bits_types_sigset_t::HDR,
    &bits_types_stack_t::HDR,
    &bits_types_struct_FILE::HDR,
    &bits_types_struct_itimerspec::HDR,
    &bits_types_struct_sigevent::HDR,
    &bits_types_struct_sigstack::HDR,
    &bits_types_struct_timespec::HDR,
    &bits_types_struct_timeval::HDR,
    &bits_types_struct_tm::HDR,
    &bits_types_suseconds_t::HDR,
    &bits_types_time_t::HDR,
    &bits_types_timer_t::HDR,
    &gnu_lib_names_64::HDR,
    &gnu_lib_names::HDR,
    &gnu_libc_version::HDR,
    &net_ethernet::HDR,
    &net_if::HDR,
    &net_if_arp::HDR,
    &net_route::HDR,
    &netinet_ether::HDR,
    &netinet_icmp6::HDR,
    &netinet_if_ether::HDR,
    &netinet_if_fddi::HDR,
    &netinet_igmp::HDR,
    &netinet_in::HDR,
    &netinet_in_systm::HDR,
    &netinet_ip::HDR,
    &netinet_ip6::HDR,
    &netinet_ip_icmp::HDR,
    &netinet_tcp::HDR,
    &netinet_udp::HDR,
    &netpacket_packet::HDR,
    &rpc_auth::HDR,
    &rpc_auth_des::HDR,
    &rpc_auth_unix::HDR,
    &rpc_clnt::HDR,
    &rpc_clnt_stat::HDR,
    &rpc_des_crypt::HDR,
    &rpc_key_prot::HDR,
    &rpc_netdb::HDR,
    &rpc_pmap_clnt::HDR,
    &rpc_pmap_prot::HDR,
    &rpc_pmap_rmt::HDR,
    &rpc_rpc::HDR,
    &rpc_rpc_msg::HDR,
    &rpc_svc::HDR,
    &rpc_svc_auth::HDR,
    &rpc_types::HDR,
    &rpc_xdr::HDR,
    &sys_cdefs::HDR,
    &sys_dir::HDR,
    &sys_errno::HDR,
    &sys_fcntl::HDR,
    &sys_gmon::HDR,
    &sys_gmon_out::HDR,
    &sys_io::HDR,
    &sys_ipc::HDR,
    &sys_kd::HDR,
    &sys_msg::HDR,
    &sys_mtio::HDR,
    &sys_param::HDR,
    &sys_perm::HDR,
    &sys_poll::HDR,
    &sys_procfs::HDR,
    &sys_profil::HDR,
    &sys_queue::HDR,
    &sys_sem::HDR,
    &sys_shm::HDR,
    &sys_signal::HDR,
    &sys_single_threaded::HDR,
    &sys_socket::HDR,
    &sys_syslog::HDR,
    &sys_termios::HDR,
    &sys_ttychars::HDR,
    &sys_ucontext::HDR,
    &sys_un::HDR,
    &sys_unistd::HDR,
    &sys_user::HDR,
    &sys_vfs::HDR,
    &sys_vlimit::HDR,
    &sys_vt::HDR,
    &sys_platform_x86::HDR,
];
