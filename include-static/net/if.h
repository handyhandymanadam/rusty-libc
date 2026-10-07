#ifndef _NET_IF_H
#define _NET_IF_H 1
#include <sys/socket.h>
#ifndef __caddr_t_defined
#define __caddr_t_defined 1
typedef char *caddr_t;
#endif

#define IFF_ALLMULTI 512
#define IFF_AUTOMEDIA 16384
#define IFF_BROADCAST 2
#define IFF_DEBUG 4
#define IFF_DYNAMIC 32768
#define IFF_LOOPBACK 8
#define IFF_MASTER 1024
#define IFF_MULTICAST 4096
#define IFF_NOARP 128
#define IFF_NOTRAILERS 32
#define IFF_POINTOPOINT 16
#define IFF_PORTSEL 8192
#define IFF_PROMISC 256
#define IFF_RUNNING 64
#define IFF_SLAVE 2048
#define IFF_UP 1
#define IFHWADDRLEN 6
#define IFNAMSIZ 16
#define IF_NAMESIZE 16

struct if_nameindex {
  unsigned int if_index;
  char *if_name;
};

struct ifmap {
  unsigned long int mem_start;
  unsigned long int mem_end;
  unsigned short int base_addr;
  unsigned char irq;
  unsigned char dma;
  unsigned char port;
};

struct ifreq {
  union {
    char ifrn_name[IFNAMSIZ];
  } ifr_ifrn;
  union {
    struct sockaddr ifru_addr;
    struct sockaddr ifru_dstaddr;
    struct sockaddr ifru_broadaddr;
    struct sockaddr ifru_netmask;
    struct sockaddr ifru_hwaddr;
    short int ifru_flags;
    int ifru_ivalue;
    int ifru_mtu;
    struct ifmap ifru_map;
    char ifru_slave[IFNAMSIZ];
    char ifru_newname[IFNAMSIZ];
    caddr_t ifru_data;
  } ifr_ifru;
};
#define ifr_name ifr_ifrn.ifrn_name
#define ifr_hwaddr ifr_ifru.ifru_hwaddr
#define ifr_addr ifr_ifru.ifru_addr
#define ifr_dstaddr ifr_ifru.ifru_dstaddr
#define ifr_broadaddr ifr_ifru.ifru_broadaddr
#define ifr_netmask ifr_ifru.ifru_netmask
#define ifr_flags ifr_ifru.ifru_flags
#define ifr_metric ifr_ifru.ifru_ivalue
#define ifr_ifindex ifr_ifru.ifru_ivalue
#define ifr_mtu ifr_ifru.ifru_mtu
#define ifr_map ifr_ifru.ifru_map
#define ifr_slave ifr_ifru.ifru_slave
#define ifr_data ifr_ifru.ifru_data
#define ifr_qlen ifr_ifru.ifru_ivalue
#define ifr_newname ifr_ifru.ifru_newname

#define _IOT_ifreq _IOT (_IOTS (char), IFNAMSIZ, _IOTS (char), 16, 0, 0)
#define _IOT_ifreq_short _IOT (_IOTS (char), IFNAMSIZ, _IOTS (short), 1, 0, 0)
#define _IOT_ifreq_int _IOT (_IOTS (char), IFNAMSIZ, _IOTS (int), 1, 0, 0)

struct ifconf {
  int ifc_len;
  union {
    caddr_t ifcu_buf;
    struct ifreq *ifcu_req;
  } ifc_ifcu;
};
#define ifc_buf ifc_ifcu.ifcu_buf
#define ifc_req ifc_ifcu.ifcu_req
#define _IOT_ifconf _IOT (_IOTS (struct ifconf), 1, 0, 0, 0, 0)

#include <bits/rlibc-net-if.h>
#endif
