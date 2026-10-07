#ifndef _NETINET_UDP_H
#define _NETINET_UDP_H 1
#include <stdint.h>

#define SOL_UDP 17
#define UDP_CORK 1
#define UDP_ENCAP 100
#define UDP_ENCAP_ESPINUDP 2
#define UDP_ENCAP_ESPINUDP_NON_IKE 1
#define UDP_ENCAP_GTP0 4
#define UDP_ENCAP_GTP1U 5
#define UDP_ENCAP_L2TPINUDP 3
#define UDP_GRO 104
#define UDP_NO_CHECK6_RX 102
#define UDP_NO_CHECK6_TX 101
#define UDP_SEGMENT 103

struct udphdr {
  __extension__ union {
    struct {
      uint16_t uh_sport;
      uint16_t uh_dport;
      uint16_t uh_ulen;
      uint16_t uh_sum;
    };
    struct {
      uint16_t source;
      uint16_t dest;
      uint16_t len;
      uint16_t check;
    };
  };
};

#endif
