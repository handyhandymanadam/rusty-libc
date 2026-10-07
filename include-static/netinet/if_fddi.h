#ifndef _NETINET_IF_FDDI_H
#define _NETINET_IF_FDDI_H 1
#include <features.h>
#include <sys/types.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

struct fddi_8022_1_hdr {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
} __attribute__((packed));

struct fddi_8022_2_hdr {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl_1;
  uint8_t ctrl_2;
} __attribute__((packed));

struct fddi_snap_hdr {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
  uint8_t oui[3];
  uint16_t ethertype;
} __attribute__((packed));

struct fddihdr {
  uint8_t fc;
  uint8_t daddr[6];
  uint8_t saddr[6];
  union {
    struct fddi_8022_1_hdr llc_8022_1;
    struct fddi_8022_2_hdr llc_8022_2;
    struct fddi_snap_hdr llc_snap;
  } hdr;
} __attribute__((packed));

#ifdef __USE_MISC
struct fddi_header {
  uint8_t fddi_fc;
  uint8_t fddi_dhost[6];
  uint8_t fddi_shost[6];
};
#endif
#define FDDI_EXTENDED_SAP 0xAA
#define FDDI_FC_K_ALEN_16 0x00
#define FDDI_FC_K_ALEN_48 0x40
#define FDDI_FC_K_ALEN_MASK 0x40
#define FDDI_FC_K_ASYNC_LLC_DEF 0x54
#define FDDI_FC_K_ASYNC_LLC_MAX 0x5F
#define FDDI_FC_K_ASYNC_LLC_MIN 0x50
#define FDDI_FC_K_CLASS_ASYNC 0x00
#define FDDI_FC_K_CLASS_MASK 0x80
#define FDDI_FC_K_CLASS_SYNC 0x80
#define FDDI_FC_K_CONTROL_MASK 0x0f
#define FDDI_FC_K_FORMAT_FUTURE 0x30
#define FDDI_FC_K_FORMAT_IMPLEMENTOR 0x20
#define FDDI_FC_K_FORMAT_LLC 0x10
#define FDDI_FC_K_FORMAT_MANAGEMENT 0x00
#define FDDI_FC_K_FORMAT_MASK 0x30
#define FDDI_FC_K_IMPLEMENTOR_MAX 0x6F
#define FDDI_FC_K_IMPLEMENTOR_MIN 0x60
#define FDDI_FC_K_MAC_MAX 0xCF
#define FDDI_FC_K_MAC_MIN 0xC1
#define FDDI_FC_K_NON_RESTRICTED_TOKEN 0x80
#define FDDI_FC_K_RESERVED_MAX 0x7F
#define FDDI_FC_K_RESERVED_MIN 0x70
#define FDDI_FC_K_RESTRICTED_TOKEN 0xC0
#define FDDI_FC_K_SMT_MAX 0x4F
#define FDDI_FC_K_SMT_MIN 0x41
#define FDDI_FC_K_SYNC_LLC_MAX 0xD7
#define FDDI_FC_K_SYNC_LLC_MIN 0xD0
#define FDDI_FC_K_VOID 0x00
#define FDDI_K_8022_DLEN 4475
#define FDDI_K_8022_HLEN 16
#define FDDI_K_8022_ZLEN 16
#define FDDI_K_ALEN 6
#define FDDI_K_LLC_LEN 4491
#define FDDI_K_LLC_ZLEN 13
#define FDDI_K_OUI_LEN 3
#define FDDI_K_SNAP_DLEN 4470
#define FDDI_K_SNAP_HLEN 21
#define FDDI_K_SNAP_ZLEN 21
#define FDDI_UI_CMD 0x03
#ifdef __cplusplus
}
#endif
#endif
