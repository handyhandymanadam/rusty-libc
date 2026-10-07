#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H 1
#include <stddef.h>
#include <stdint.h>
#include <bits/types/struct_timespec.h>
#ifndef __socklen_t_defined
#define __socklen_t_defined 1
typedef unsigned int socklen_t;
#endif
#include <bits/sockaddr.h>
#ifndef __sa_family_t_defined
#define __sa_family_t_defined 1
typedef unsigned short int sa_family_t;
#endif
#ifndef __pid_t_defined
#define __pid_t_defined 1
typedef int pid_t;
#endif
#ifndef __uid_t_defined
#define __uid_t_defined 1
typedef unsigned int uid_t;
#endif
#ifndef __gid_t_defined
#define __gid_t_defined 1
typedef unsigned int gid_t;
#endif
#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef long ssize_t;
#endif
#ifndef __iovec_defined
#define __iovec_defined 1
struct iovec {
  void *iov_base;
  size_t iov_len;
};
#endif

#define AF_ALG 38
#define AF_APPLETALK 5
#define AF_ASH 18
#define AF_ATMPVC 8
#define AF_ATMSVC 20
#define AF_AX25 3
#define AF_BLUETOOTH 31
#define AF_BRIDGE 7
#define AF_CAIF 37
#define AF_CAN 29
#define AF_DECnet 12
#define AF_ECONET 19
#define AF_FILE 1
#define AF_IB 27
#define AF_IEEE802154 36
#define AF_INET 2
#define AF_INET6 10
#define AF_IPX 4
#define AF_IRDA 23
#define AF_ISDN 34
#define AF_IUCV 32
#define AF_KCM 41
#define AF_KEY 15
#define AF_LLC 26
#define AF_LOCAL 1
#define AF_MAX 46
#define AF_MCTP 45
#define AF_MPLS 28
#define AF_NETBEUI 13
#define AF_NETLINK 16
#define AF_NETROM 6
#define AF_NFC 39
#define AF_PACKET 17
#define AF_PHONET 35
#define AF_PPPOX 24
#define AF_QIPCRTR 42
#define AF_RDS 21
#define AF_ROSE 11
#define AF_ROUTE 16
#define AF_RXRPC 33
#define AF_SECURITY 14
#define AF_SMC 43
#define AF_SNA 22
#define AF_TIPC 30
#define AF_UNIX 1
#define AF_UNSPEC 0
#define AF_VSOCK 40
#define AF_WANPIPE 25
#define AF_X25 9
#define AF_XDP 44
#define FIOGETOWN 35075
#define FIOSETOWN 35073
#define MSG_BATCH 262144
#define MSG_CMSG_CLOEXEC 1073741824
#define MSG_CONFIRM 2048
#define MSG_CTRUNC 8
#define MSG_DONTROUTE 4
#define MSG_DONTWAIT 64
#define MSG_EOR 128
#define MSG_ERRQUEUE 8192
#define MSG_FASTOPEN 536870912
#define MSG_FIN 512
#define MSG_MORE 32768
#define MSG_NOSIGNAL 16384
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_PROXY 16
#define MSG_RST 4096
#define MSG_SOCK_DEVMEM 33554432
#define MSG_SYN 1024
#define MSG_TRUNC 32
#define MSG_TRYHARD 4
#define MSG_WAITALL 256
#define MSG_WAITFORONE 65536
#define MSG_ZEROCOPY 67108864
#define PF_ALG 38
#define PF_APPLETALK 5
#define PF_ASH 18
#define PF_ATMPVC 8
#define PF_ATMSVC 20
#define PF_AX25 3
#define PF_BLUETOOTH 31
#define PF_BRIDGE 7
#define PF_CAIF 37
#define PF_CAN 29
#define PF_DECnet 12
#define PF_ECONET 19
#define PF_FILE 1
#define PF_IB 27
#define PF_IEEE802154 36
#define PF_INET 2
#define PF_INET6 10
#define PF_IPX 4
#define PF_IRDA 23
#define PF_ISDN 34
#define PF_IUCV 32
#define PF_KCM 41
#define PF_KEY 15
#define PF_LLC 26
#define PF_LOCAL 1
#define PF_MAX 46
#define PF_MCTP 45
#define PF_MPLS 28
#define PF_NETBEUI 13
#define PF_NETLINK 16
#define PF_NETROM 6
#define PF_NFC 39
#define PF_PACKET 17
#define PF_PHONET 35
#define PF_PPPOX 24
#define PF_QIPCRTR 42
#define PF_RDS 21
#define PF_ROSE 11
#define PF_ROUTE 16
#define PF_RXRPC 33
#define PF_SECURITY 14
#define PF_SMC 43
#define PF_SNA 22
#define PF_TIPC 30
#define PF_UNIX 1
#define PF_UNSPEC 0
#define PF_VSOCK 40
#define PF_WANPIPE 25
#define PF_X25 9
#define PF_XDP 44
#define SCM_CREDENTIALS 2
#define SCM_DEVMEM_DMABUF 79
#define SCM_DEVMEM_LINEAR 78
#define SCM_INQ 84
#define SCM_PIDFD 4
#define SCM_RIGHTS 1
#define SCM_SECURITY 3
#define SCM_TIMESTAMP 29
#define SCM_TIMESTAMPING 37
#define SCM_TIMESTAMPING_OPT_STATS 54
#define SCM_TIMESTAMPING_PKTINFO 58
#define SCM_TIMESTAMPNS 35
#define SCM_TS_OPT_ID 81
#define SCM_TXTIME 61
#define SCM_WIFI_STATUS 41
#define SHUT_RD 0
#define SHUT_RDWR 2
#define SHUT_WR 1
#define SIOCATMARK 35077
#define SIOCGPGRP 35076
#define SIOCGSTAMPNS_OLD 35079
#define SIOCGSTAMP_OLD 35078
#define SIOCSPGRP 35074
#define SOCK_CLOEXEC 524288
#define SOCK_DCCP 6
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 2048
#define SOCK_PACKET 10
#define SOCK_RAW 3
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5
#define SOCK_STREAM 1
#define SOL_AAL 265
#define SOL_ALG 279
#define SOL_ATM 264
#define SOL_BLUETOOTH 274
#define SOL_CAIF 278
#define SOL_DCCP 269
#define SOL_DECNET 261
#define SOL_IRDA 266
#define SOL_IUCV 277
#define SOL_KCM 281
#define SOL_LLC 268
#define SOL_MCTP 285
#define SOL_MPTCP 284
#define SOL_NETBEUI 267
#define SOL_NETLINK 270
#define SOL_NFC 280
#define SOL_PACKET 263
#define SOL_PNPIPE 275
#define SOL_PPPOL2TP 273
#define SOL_RAW 255
#define SOL_RDS 276
#define SOL_RXRPC 272
#define SOL_SMC 286
#define SOL_SOCKET 1
#define SOL_TIPC 271
#define SOL_TLS 282
#define SOL_VSOCK 287
#define SOL_X25 262
#define SOL_XDP 283
#define SOMAXCONN 4096
#define SO_ACCEPTCONN 30
#define SO_ATTACH_BPF 50
#define SO_ATTACH_FILTER 26
#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52
#define SO_BINDTODEVICE 25
#define SO_BINDTOIFINDEX 62
#define SO_BPF_EXTENSIONS 48
#define SO_BROADCAST 6
#define SO_BSDCOMPAT 14
#define SO_BUF_LOCK 72
#define SO_BUSY_POLL 46
#define SO_BUSY_POLL_BUDGET 70
#define SO_CNX_ADVICE 53
#define SO_COOKIE 57
#define SO_DEBUG 1
#define SO_DETACH_BPF 27
#define SO_DETACH_FILTER 27
#define SO_DETACH_REUSEPORT_BPF 68
#define SO_DEVMEM_DMABUF 79
#define SO_DEVMEM_DONTNEED 80
#define SO_DEVMEM_LINEAR 78
#define SO_DOMAIN 39
#define SO_DONTROUTE 5
#define SO_ERROR 4
#define SO_GET_FILTER 26
#define SO_INCOMING_CPU 49
#define SO_INCOMING_NAPI_ID 56
#define SO_INQ 84
#define SO_KEEPALIVE 9
#define SO_LINGER 13
#define SO_LOCK_FILTER 44
#define SO_MARK 36
#define SO_MAX_PACING_RATE 47
#define SO_MEMINFO 55
#define SO_NETNS_COOKIE 71
#define SO_NOFCS 43
#define SO_NO_CHECK 11
#define SO_OOBINLINE 10
#define SO_PASSCRED 16
#define SO_PASSPIDFD 76
#define SO_PASSRIGHTS 83
#define SO_PASSSEC 34
#define SO_PEEK_OFF 42
#define SO_PEERCRED 17
#define SO_PEERGROUPS 59
#define SO_PEERNAME 28
#define SO_PEERPIDFD 77
#define SO_PEERSEC 31
#define SO_PREFER_BUSY_POLL 69
#define SO_PRIORITY 12
#define SO_PROTOCOL 38
#define SO_RCVBUF 8
#define SO_RCVBUFFORCE 33
#define SO_RCVLOWAT 18
#define SO_RCVMARK 75
#define SO_RCVPRIORITY 82
#define SO_RCVTIMEO 20
#define SO_RCVTIMEO_NEW 66
#define SO_RCVTIMEO_OLD 20
#define SO_RESERVE_MEM 73
#define SO_REUSEADDR 2
#define SO_REUSEPORT 15
#define SO_RXQ_OVFL 40
#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_NETWORK 24
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SELECT_ERR_QUEUE 45
#define SO_SNDBUF 7
#define SO_SNDBUFFORCE 32
#define SO_SNDLOWAT 19
#define SO_SNDTIMEO 21
#define SO_SNDTIMEO_NEW 67
#define SO_SNDTIMEO_OLD 21
#define SO_TIMESTAMP 29
#define SO_TIMESTAMPING 37
#define SO_TIMESTAMPING_NEW 65
#define SO_TIMESTAMPING_OLD 37
#define SO_TIMESTAMPNS 35
#define SO_TIMESTAMPNS_NEW 64
#define SO_TIMESTAMPNS_OLD 35
#define SO_TIMESTAMP_NEW 63
#define SO_TIMESTAMP_OLD 29
#define SO_TXREHASH 74
#define SO_TXTIME 61
#define SO_TYPE 3
#define SO_WIFI_STATUS 41
#define SO_ZEROCOPY 60

struct sockaddr {
  sa_family_t sa_family;
  char sa_data[14];
};

#define _SS_SIZE 128
typedef unsigned long int __ss_aligntype;
#define _SS_PADSIZE (_SS_SIZE - __SOCKADDR_COMMON_SIZE - sizeof (__ss_aligntype))
struct sockaddr_storage {
  __SOCKADDR_COMMON (ss_);
  char __ss_padding[_SS_PADSIZE];
  __ss_aligntype __ss_align;
};

struct osockaddr {
  unsigned short int sa_family;
  unsigned char sa_data[14];
};

struct msghdr {
  void *msg_name;
  socklen_t msg_namelen;
  struct iovec *msg_iov;
  size_t msg_iovlen;
  void *msg_control;
  size_t msg_controllen;
  int msg_flags;
};

struct cmsghdr {
  size_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
  __extension__ unsigned char __cmsg_data[];
};

struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};

struct linger {
  int l_onoff;
  int l_linger;
};

struct ucred {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

#define CMSG_DATA(cmsg) ((cmsg)->__cmsg_data)
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0)
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN (len) + CMSG_ALIGN (sizeof (struct cmsghdr)))
#define CMSG_LEN(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))

#include <bits/rlibc-net-sock.h>
#endif
