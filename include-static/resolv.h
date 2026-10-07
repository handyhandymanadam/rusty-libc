#ifndef _RESOLV_H
#define _RESOLV_H 1
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#define MAXDFLSRCH 3
#define MAXDNSRCH 6
#define MAXNS 3
#define MAXRESOLVSORT 10
#define RES_DEBUG 2
#define RES_DEFAULT 704
#define RES_DEFNAMES 128
#define RES_DFLRETRY 2
#define RES_DNSRCH 512
#define RES_IGNTC 32
#define RES_INIT 1
#define RES_MAXNDOTS 15
#define RES_MAXRETRANS 30
#define RES_MAXRETRY 5
#define RES_MAXTIME 65535
#define RES_NOAAAA 134217728
#define RES_NOALIASES 4096
#define RES_NORELOAD 33554432
#define RES_NOTLDQUERY 16777216
#define RES_RECURSE 64
#define RES_ROTATE 16384
#define RES_SNGLKUP 2097152
#define RES_SNGLKUPREOP 4194304
#define RES_STAYOPEN 256
#define RES_STRICTERR 268435456
#define RES_TIMEOUT 5
#define RES_TRUSTAD 67108864
#define RES_USEVC 8
#define RES_USE_DNSSEC 8388608
#define RES_USE_EDNS0 1048576
#define RES_PRF_ADD 128
#define RES_PRF_ANS 32
#define RES_PRF_AUTH 64
#define RES_PRF_CLASS 4
#define RES_PRF_CMD 8
#define RES_PRF_HEAD1 256
#define RES_PRF_HEAD2 512
#define RES_PRF_HEADX 2048
#define RES_PRF_INIT 16384
#define RES_PRF_QUERY 4096
#define RES_PRF_QUES 16
#define RES_PRF_REPLY 8192
#define RES_PRF_STATS 1
#define RES_PRF_TTLID 1024
#define RES_PRF_UPDATE 2


struct __res_state {
  int retrans;
  int retry;
  unsigned long options;
  int nscount;
  struct sockaddr_in nsaddr_list[MAXNS];
#define nsaddr nsaddr_list[0]
  unsigned short id;
  char *dnsrch[MAXDNSRCH + 1];
  char defdname[256];
  unsigned long pfcode;
  unsigned ndots:4;
  unsigned nsort:4;
  unsigned ipv6_unavail:1;
  unsigned unused:23;
  struct {
    struct in_addr addr;
    uint32_t mask;
  } sort_list[MAXRESOLVSORT];
  void *__glibc_unused_qhook;
  void *__glibc_unused_rhook;
  int res_h_errno;
  int _vcsock;
  unsigned int _flags;
  union {
    char pad[52];
    struct {
      uint16_t nscount;
      uint16_t nsmap[MAXNS];
      int nssocks[MAXNS];
      uint16_t nscount6;
      uint16_t nsinit;
      struct sockaddr_in6 *nsaddrs[MAXNS];
      unsigned int __glibc_extension_index;
    } _ext;
  } _u;
};
typedef struct __res_state *res_state;

#define _res (*__res_state())

#define res_init __res_init
#define res_ninit __res_ninit
#define res_nclose __res_nclose
#define res_iclose __res_iclose
#define loc_ntoa __loc_ntoa

#include <bits/rlibc-net-resolv.h>
#endif
