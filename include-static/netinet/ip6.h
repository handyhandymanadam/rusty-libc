#ifndef _RLIBC_NETINET_IP6_H
#define _RLIBC_NETINET_IP6_H 1
#include <stdint.h>
#include <netinet/in.h>

struct ip6_hdr {
  union {
    struct ip6_hdrctl {
      uint32_t ip6_un1_flow;
      uint16_t ip6_un1_plen;
      uint8_t ip6_un1_nxt;
      uint8_t ip6_un1_hlim;
    } ip6_un1;
    uint8_t ip6_un2_vfc;
  } ip6_ctlun;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
};
#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim

struct ip6_ext { uint8_t ip6e_nxt; uint8_t ip6e_len; };
struct ip6_hbh { uint8_t ip6h_nxt; uint8_t ip6h_len; };
struct ip6_dest { uint8_t ip6d_nxt; uint8_t ip6d_len; };
struct ip6_rthdr { uint8_t ip6r_nxt; uint8_t ip6r_len; uint8_t ip6r_type; uint8_t ip6r_segleft; };
struct ip6_rthdr0 { uint8_t ip6r0_nxt; uint8_t ip6r0_len; uint8_t ip6r0_type; uint8_t ip6r0_segleft; uint32_t ip6r0_reserved; };
struct ip6_frag { uint8_t ip6f_nxt; uint8_t ip6f_reserved; uint16_t ip6f_offlg; uint32_t ip6f_ident; };

#define IP6F_OFF_MASK 0xf8ff
#define IP6F_RESERVED_MASK 0x0600
#define IP6F_MORE_FRAG 0x0100

struct ip6_opt { uint8_t ip6o_type; uint8_t ip6o_len; };
#define IP6OPT_TYPE(o) ((o) & 0xc0)
#define IP6OPT_TYPE_SKIP 0x00
#define IP6OPT_TYPE_DISCARD 0x40
#define IP6OPT_TYPE_FORCEICMP 0x80
#define IP6OPT_TYPE_ICMP 0xc0
#define IP6OPT_TYPE_MUTABLE 0x20
#define IP6OPT_PAD1 0
#define IP6OPT_PADN 1
#define IP6OPT_JUMBO 0xc2
#define IP6OPT_NSAP_ADDR 0xc3
#define IP6OPT_TUNNEL_LIMIT 0x04
#define IP6OPT_ROUTER_ALERT 0x05
#define IP6OPT_JUMBO_LEN 6
#endif
