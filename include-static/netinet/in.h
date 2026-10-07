#ifndef _NETINET_IN_H
#define _NETINET_IN_H 1
#include <stdint.h>
#include <sys/socket.h>

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr {
  in_addr_t s_addr;
};

#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN 16
#define IN_CLASSA_HOST 0x00ffffffU
#define IN_CLASSA_MAX 128
#define IN_CLASSA_NET 0xff000000U
#define IN_CLASSA_NSHIFT 24
#define IN_CLASSB_HOST 0x0000ffffU
#define IN_CLASSB_MAX 65536
#define IN_CLASSB_NET 0xffff0000U
#define IN_CLASSB_NSHIFT 16
#define IN_CLASSC_HOST 0x000000ffU
#define IN_CLASSC_NET 0xffffff00U
#define IN_CLASSC_NSHIFT 8
#define IN_LOOPBACKNET 127
#define IPPROTO_AH 51
#define IPPROTO_BEETPH 94
#define IPPROTO_COMP 108
#define IPPROTO_DCCP 33
#define IPPROTO_DSTOPTS 60
#define IPPROTO_EGP 8
#define IPPROTO_ENCAP 98
#define IPPROTO_ESP 50
#define IPPROTO_ETHERNET 143
#define IPPROTO_FRAGMENT 44
#define IPPROTO_GRE 47
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58
#define IPPROTO_IDP 22
#define IPPROTO_IGMP 2
#define IPPROTO_IP 0
#define IPPROTO_IPIP 4
#define IPPROTO_IPV6 41
#define IPPROTO_L2TP 115
#define IPPROTO_MH 135
#define IPPROTO_MPLS 137
#define IPPROTO_MPTCP 262
#define IPPROTO_MTP 92
#define IPPROTO_NONE 59
#define IPPROTO_PIM 103
#define IPPROTO_PUP 12
#define IPPROTO_RAW 255
#define IPPROTO_ROUTING 43
#define IPPROTO_RSVP 46
#define IPPROTO_SCTP 132
#define IPPROTO_SMC 256
#define IPPROTO_TCP 6
#define IPPROTO_TP 29
#define IPPROTO_UDP 17
#define IPPROTO_UDPLITE 136
#define IPV6_2292DSTOPTS 4
#define IPV6_2292HOPLIMIT 8
#define IPV6_2292HOPOPTS 3
#define IPV6_2292PKTINFO 2
#define IPV6_2292PKTOPTIONS 6
#define IPV6_2292RTHDR 5
#define IPV6_ADDRFORM 1
#define IPV6_ADDR_PREFERENCES 72
#define IPV6_ADD_MEMBERSHIP 20
#define IPV6_AUTHHDR 10
#define IPV6_AUTOFLOWLABEL 70
#define IPV6_CHECKSUM 7
#define IPV6_DONTFRAG 62
#define IPV6_DROP_MEMBERSHIP 21
#define IPV6_DSTOPTS 59
#define IPV6_FREEBIND 78
#define IPV6_HDRINCL 36
#define IPV6_HOPLIMIT 52
#define IPV6_HOPOPTS 54
#define IPV6_IPSEC_POLICY 34
#define IPV6_JOIN_ANYCAST 27
#define IPV6_JOIN_GROUP 20
#define IPV6_LEAVE_ANYCAST 28
#define IPV6_LEAVE_GROUP 21
#define IPV6_MINHOPCOUNT 73
#define IPV6_MTU 24
#define IPV6_MTU_DISCOVER 23
#define IPV6_MULTICAST_ALL 29
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_IF 17
#define IPV6_MULTICAST_LOOP 19
#define IPV6_NEXTHOP 9
#define IPV6_ORIGDSTADDR 74
#define IPV6_PATHMTU 61
#define IPV6_PKTINFO 50
#define IPV6_PMTUDISC_DO 2
#define IPV6_PMTUDISC_DONT 0
#define IPV6_PMTUDISC_INTERFACE 4
#define IPV6_PMTUDISC_OMIT 5
#define IPV6_PMTUDISC_PROBE 3
#define IPV6_PMTUDISC_WANT 1
#define IPV6_RECVDSTOPTS 58
#define IPV6_RECVERR 25
#define IPV6_RECVERR_RFC4884 31
#define IPV6_RECVFRAGSIZE 77
#define IPV6_RECVHOPLIMIT 51
#define IPV6_RECVHOPOPTS 53
#define IPV6_RECVORIGDSTADDR 74
#define IPV6_RECVPATHMTU 60
#define IPV6_RECVPKTINFO 49
#define IPV6_RECVRTHDR 56
#define IPV6_RECVTCLASS 66
#define IPV6_ROUTER_ALERT 22
#define IPV6_ROUTER_ALERT_ISOLATE 30
#define IPV6_RTHDR 57
#define IPV6_RTHDRDSTOPTS 55
#define IPV6_RTHDR_LOOSE 0
#define IPV6_RTHDR_STRICT 1
#define IPV6_RTHDR_TYPE_0 0
#define IPV6_RXDSTOPTS 59
#define IPV6_RXHOPOPTS 54
#define IPV6_TCLASS 67
#define IPV6_TRANSPARENT 75
#define IPV6_UNICAST_HOPS 16
#define IPV6_UNICAST_IF 76
#define IPV6_V6ONLY 26
#define IPV6_XFRM_POLICY 35
#define IP_ADD_MEMBERSHIP 35
#define IP_ADD_SOURCE_MEMBERSHIP 39
#define IP_BIND_ADDRESS_NO_PORT 24
#define IP_BLOCK_SOURCE 38
#define IP_CHECKSUM 23
#define IP_DEFAULT_MULTICAST_LOOP 1
#define IP_DEFAULT_MULTICAST_TTL 1
#define IP_DROP_MEMBERSHIP 36
#define IP_DROP_SOURCE_MEMBERSHIP 40
#define IP_FREEBIND 15
#define IP_HDRINCL 3
#define IP_IPSEC_POLICY 16
#define IP_LOCAL_PORT_RANGE 51
#define IP_MAX_MEMBERSHIPS 20
#define IP_MINTTL 21
#define IP_MSFILTER 41
#define IP_MTU 14
#define IP_MTU_DISCOVER 10
#define IP_MULTICAST_ALL 49
#define IP_MULTICAST_IF 32
#define IP_MULTICAST_LOOP 34
#define IP_MULTICAST_TTL 33
#define IP_NODEFRAG 22
#define IP_OPTIONS 4
#define IP_ORIGDSTADDR 20
#define IP_PASSSEC 18
#define IP_PKTINFO 8
#define IP_PKTOPTIONS 9
#define IP_PMTUDISC 10
#define IP_PMTUDISC_DO 2
#define IP_PMTUDISC_DONT 0
#define IP_PMTUDISC_INTERFACE 4
#define IP_PMTUDISC_OMIT 5
#define IP_PMTUDISC_PROBE 3
#define IP_PMTUDISC_WANT 1
#define IP_PROTOCOL 52
#define IP_RECVERR 11
#define IP_RECVERR_RFC4884 26
#define IP_RECVFRAGSIZE 25
#define IP_RECVOPTS 6
#define IP_RECVORIGDSTADDR 20
#define IP_RECVRETOPTS 7
#define IP_RECVTOS 13
#define IP_RECVTTL 12
#define IP_RETOPTS 7
#define IP_ROUTER_ALERT 5
#define IP_TOS 1
#define IP_TRANSPARENT 19
#define IP_TTL 2
#define IP_UNBLOCK_SOURCE 37
#define IP_UNICAST_IF 50
#define IP_XFRM_POLICY 17
#define MCAST_BLOCK_SOURCE 43
#define MCAST_EXCLUDE 0
#define MCAST_INCLUDE 1
#define MCAST_JOIN_GROUP 42
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_GROUP 45
#define MCAST_LEAVE_SOURCE_GROUP 47
#define MCAST_MSFILTER 48
#define MCAST_UNBLOCK_SOURCE 44
#define SOL_ICMPV6 58
#define SOL_IP 0
#define SOL_IPV6 41
#define INADDR_ANY ((in_addr_t) 0x00000000)
#define INADDR_BROADCAST ((in_addr_t) 0xffffffff)
#define INADDR_NONE ((in_addr_t) 0xffffffff)
#define INADDR_LOOPBACK ((in_addr_t) 0x7f000001)
#define INADDR_UNSPEC_GROUP ((in_addr_t) 0xe0000000)
#define INADDR_ALLHOSTS_GROUP ((in_addr_t) 0xe0000001)
#define INADDR_ALLRTRS_GROUP ((in_addr_t) 0xe0000002)
#define INADDR_ALLSNOOPERS_GROUP ((in_addr_t) 0xe000006a)
#define INADDR_MAX_LOCAL_GROUP ((in_addr_t) 0xe00000ff)
#define INADDR_DUMMY ((in_addr_t) 0xc0000008)
#define IPPORT_ECHO 7
#define IPPORT_DISCARD 9
#define IPPORT_SYSTAT 11
#define IPPORT_DAYTIME 13
#define IPPORT_NETSTAT 15
#define IPPORT_FTP 21
#define IPPORT_TELNET 23
#define IPPORT_SMTP 25
#define IPPORT_TIMESERVER 37
#define IPPORT_NAMESERVER 42
#define IPPORT_WHOIS 43
#define IPPORT_MTP 57
#define IPPORT_TFTP 69
#define IPPORT_RJE 77
#define IPPORT_FINGER 79
#define IPPORT_TTYLINK 87
#define IPPORT_SUPDUP 95
#define IPPORT_EXECSERVER 512
#define IPPORT_LOGINSERVER 513
#define IPPORT_CMDSERVER 514
#define IPPORT_EFSSERVER 520
#define IPPORT_BIFFUDP 512
#define IPPORT_WHOSERVER 513
#define IPPORT_ROUTESERVER 520
#define IPPORT_RESERVED 1024
#define IPPORT_USERRESERVED 5000

struct in6_addr {
  union {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
  } __in6_u;
#define s6_addr __in6_u.__u6_addr8
#define s6_addr16 __in6_u.__u6_addr16
#define s6_addr32 __in6_u.__u6_addr32
};

extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

struct sockaddr_in {
  sa_family_t sin_family;
  in_port_t sin_port;
  struct in_addr sin_addr;
  unsigned char sin_zero[sizeof (struct sockaddr) - sizeof (sa_family_t) - sizeof (in_port_t) - sizeof (struct in_addr)];
};

struct sockaddr_in6 {
  sa_family_t sin6_family;
  in_port_t sin6_port;
  uint32_t sin6_flowinfo;
  struct in6_addr sin6_addr;
  uint32_t sin6_scope_id;
};

struct ip_mreq {
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
};

struct ip_mreq_source {
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
  struct in_addr imr_sourceaddr;
};

struct ipv6_mreq {
  struct in6_addr ipv6mr_multiaddr;
  unsigned int ipv6mr_interface;
};

struct group_req {
  uint32_t gr_interface;
  struct sockaddr_storage gr_group;
};

struct group_source_req {
  uint32_t gsr_interface;
  struct sockaddr_storage gsr_group;
  struct sockaddr_storage gsr_source;
};

struct ip_msfilter {
  struct in_addr imsf_multiaddr;
  struct in_addr imsf_interface;
  uint32_t imsf_fmode;
  uint32_t imsf_numsrc;
  struct in_addr imsf_slist[1];
};
#define IP_MSFILTER_SIZE(numsrc) (sizeof (struct ip_msfilter) - sizeof (struct in_addr) + (numsrc) * sizeof (struct in_addr))

struct group_filter {
  uint32_t gf_interface;
  struct sockaddr_storage gf_group;
  uint32_t gf_fmode;
  uint32_t gf_numsrc;
  struct sockaddr_storage gf_slist[1];
};
#define GROUP_FILTER_SIZE(numsrc) (sizeof (struct group_filter) - sizeof (struct sockaddr_storage) + (numsrc) * sizeof (struct sockaddr_storage))

struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};

struct in6_pktinfo {
  struct in6_addr ipi6_addr;
  unsigned int ipi6_ifindex;
};

struct ip6_mtuinfo {
  struct sockaddr_in6 ip6m_addr;
  uint32_t ip6m_mtu;
};

#define IN_CLASSA(a) ((((in_addr_t) (a)) & 0x80000000) == 0)
#define IN_CLASSB(a) ((((in_addr_t) (a)) & 0xc0000000) == 0x80000000)
#define IN_CLASSC(a) ((((in_addr_t) (a)) & 0xe0000000) == 0xc0000000)
#define IN_CLASSD(a) ((((in_addr_t) (a)) & 0xf0000000) == 0xe0000000)
#define IN_MULTICAST(a) IN_CLASSD (a)
#define IN_EXPERIMENTAL(a) ((((in_addr_t) (a)) & 0xe0000000) == 0xe0000000)
#define IN_BADCLASS(a) ((((in_addr_t) (a)) & 0xf0000000) == 0xf0000000)
#define IN_LOOPBACK(a) ((((in_addr_t) (a)) & 0xff000000) == 0x7f000000)

#define IN6_IS_ADDR_UNSPECIFIED(a) \
  (((const uint32_t *) (a))[0] == 0 && ((const uint32_t *) (a))[1] == 0 \
   && ((const uint32_t *) (a))[2] == 0 && ((const uint32_t *) (a))[3] == 0)
#define IN6_IS_ADDR_LOOPBACK(a) \
  (((const uint32_t *) (a))[0] == 0 && ((const uint32_t *) (a))[1] == 0 \
   && ((const uint32_t *) (a))[2] == 0 && ((const uint32_t *) (a))[3] == htonl (1))
#define IN6_IS_ADDR_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
  ((((const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfe800000))
#define IN6_IS_ADDR_SITELOCAL(a) \
  ((((const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfec00000))
#define IN6_IS_ADDR_V4MAPPED(a) \
  ((((const uint32_t *) (a))[0] == 0) && (((const uint32_t *) (a))[1] == 0) \
   && (((const uint32_t *) (a))[2] == htonl (0xffff)))
#define IN6_IS_ADDR_V4COMPAT(a) \
  ((((const uint32_t *) (a))[0] == 0) && (((const uint32_t *) (a))[1] == 0) \
   && (((const uint32_t *) (a))[2] == 0) && (ntohl (((const uint32_t *) (a))[3]) > 1))
#define IN6_ARE_ADDR_EQUAL(a, b) \
  ((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0]) \
   && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1]) \
   && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2]) \
   && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))
#define IN6_IS_ADDR_MC_NODELOCAL(a) (IN6_IS_ADDR_MULTICAST (a) && ((((const uint8_t *) (a))[1] & 0xf) == 0x1))
#define IN6_IS_ADDR_MC_LINKLOCAL(a) (IN6_IS_ADDR_MULTICAST (a) && ((((const uint8_t *) (a))[1] & 0xf) == 0x2))
#define IN6_IS_ADDR_MC_SITELOCAL(a) (IN6_IS_ADDR_MULTICAST (a) && ((((const uint8_t *) (a))[1] & 0xf) == 0x5))
#define IN6_IS_ADDR_MC_ORGLOCAL(a) (IN6_IS_ADDR_MULTICAST (a) && ((((const uint8_t *) (a))[1] & 0xf) == 0x8))
#define IN6_IS_ADDR_MC_GLOBAL(a) (IN6_IS_ADDR_MULTICAST (a) && ((((const uint8_t *) (a))[1] & 0xf) == 0xe))

#include <bits/rlibc-net-in.h>

#ifdef __OPTIMIZE__
# define ntohl(x) __builtin_bswap32 (x)
# define ntohs(x) __builtin_bswap16 (x)
# define htonl(x) __builtin_bswap32 (x)
# define htons(x) __builtin_bswap16 (x)
#endif
#endif
