#ifndef _NETINET_IF_ETHER_H
#define _NETINET_IF_ETHER_H 1
#include <features.h>
#include <sys/types.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#ifdef __cplusplus
extern "C" {
#endif

struct ether_arp {
  struct arphdr ea_hdr;
  uint8_t arp_sha[ETH_ALEN];
  uint8_t arp_spa[4];
  uint8_t arp_tha[ETH_ALEN];
  uint8_t arp_tpa[4];
};
#define ETHER_MAP_IP_MULTICAST(ipaddr,enaddr) { (enaddr)[0] = 0x01; (enaddr)[1] = 0x00; (enaddr)[2] = 0x5e; (enaddr)[3] = ((uint8_t *)ipaddr)[1] & 0x7f; (enaddr)[4] = ((uint8_t *)ipaddr)[2]; (enaddr)[5] = ((uint8_t *)ipaddr)[3]; }
#define arp_hln ea_hdr.ar_hln
#define arp_hrd ea_hdr.ar_hrd
#define arp_op ea_hdr.ar_op
#define arp_pln ea_hdr.ar_pln
#define arp_pro ea_hdr.ar_pro
#ifdef __cplusplus
}
#endif
#endif
