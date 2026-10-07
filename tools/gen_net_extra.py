#!/usr/bin/env python3
import os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def macros(includes):
    src = "".join("#include <%s>\n" % i for i in includes)
    out = subprocess.run(["gcc", "-E", "-dM", "-D_GNU_SOURCE", "-x", "c", "-"], input=src, capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        m = re.match(r"#define (\w+(?:\([^)]*\))?) ?(.*)", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


def consts(hdr, deps, skip=()):
    common = ["stdint.h", "string.h", "stdlib.h", "sys/types.h", "endian.h"]
    base = macros(common + deps)
    full = macros(common + deps + [hdr])
    lines = []
    for n in sorted(full):
        if n in base and base[n] == full[n]:
            continue
        bare = re.match(r"\w+", n).group(0)
        if bare.startswith("_") and re.fullmatch(r"_[A-Z0-9_]*_H_?", bare) or bare.startswith("__") or bare in skip:
            continue
        lines.append("#define %s %s" % (n, full[n]))
    return "\n".join(lines)


HEADERS = {}

HEADERS["netinet/in_systm.h"] = dict(deps=[], guard="_NETINET_IN_SYSTM_H", includes=["stdint.h"], body="""
typedef uint16_t n_short;
typedef uint32_t n_long;
typedef uint32_t n_time;
""")

HEADERS["netinet/ip.h"] = dict(deps=["sys/types.h", "netinet/in.h", "stdint.h"], guard="_NETINET_IP_H",
    includes=["sys/types.h", "stdint.h", "endian.h", "netinet/in.h"], body="""
struct timestamp
  {
    uint8_t len;
    uint8_t ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int flags:4;
    unsigned int overflow:4;
#else
    unsigned int overflow:4;
    unsigned int flags:4;
#endif
    uint32_t data[9];
  };

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#else
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
  };

#ifdef __USE_MISC
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;
    unsigned int ip_v:4;
#else
    unsigned int ip_v:4;
    unsigned int ip_hl:4;
#endif
    uint8_t ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src, ip_dst;
  };

struct ip_timestamp
  {
    uint8_t ipt_code;
    uint8_t ipt_len;
    uint8_t ipt_ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ipt_flg:4;
    unsigned int ipt_oflw:4;
#else
    unsigned int ipt_oflw:4;
    unsigned int ipt_flg:4;
#endif
    uint32_t data[9];
  };
#endif
""")

HEADERS["netinet/ip_icmp.h"] = dict(deps=["sys/types.h", "stdint.h", "netinet/in.h", "netinet/in_systm.h", "netinet/ip.h"],
    guard="_NETINET_IP_ICMP_H", includes=["sys/types.h", "stdint.h", "netinet/in.h", "netinet/in_systm.h", "netinet/ip.h"], body="""
struct icmphdr
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t id;
      uint16_t sequence;
    } echo;
    uint32_t gateway;
    struct
    {
      uint16_t __glibc_reserved;
      uint16_t mtu;
    } frag;
  } un;
};

#ifdef __USE_MISC
struct icmp_ra_addr
{
  uint32_t ira_addr;
  uint32_t ira_preference;
};

struct icmp
{
  uint8_t  icmp_type;
  uint8_t  icmp_code;
  uint16_t icmp_cksum;
  union
  {
    unsigned char ih_pptr;
    struct in_addr ih_gwaddr;
    struct ih_idseq
    {
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;
    uint32_t ih_void;
    struct ih_pmtu
    {
      uint16_t ipm_void;
      uint16_t ipm_nextmtu;
    } ih_pmtu;
    struct ih_rtradv
    {
      uint8_t irt_num_addrs;
      uint8_t irt_wpa;
      uint16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
  union
  {
    struct
    {
      uint32_t its_otime;
      uint32_t its_rtime;
      uint32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
    } id_ip;
    struct icmp_ra_addr id_radv;
    uint32_t   id_mask;
    uint8_t    id_data[1];
  } icmp_dun;
};
#endif
""")

HEADERS["net/if_arp.h"] = dict(deps=["sys/socket.h", "stdint.h"], guard="_NET_IF_ARP_H",
    includes=["sys/socket.h", "stdint.h"], body="""
#define MAX_ADDR_LEN 7

struct arphdr
  {
    unsigned short int ar_hrd;
    unsigned short int ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    unsigned short int ar_op;
  };

struct arpreq
  {
    struct sockaddr arp_pa;
    struct sockaddr arp_ha;
    int arp_flags;
    struct sockaddr arp_netmask;
    char arp_dev[16];
  };

struct arpreq_old
  {
    struct sockaddr arp_pa;
    struct sockaddr arp_ha;
    int arp_flags;
    struct sockaddr arp_netmask;
  };

struct arpd_request
  {
    unsigned short int req;
    uint32_t ip;
    unsigned long int dev;
    unsigned long int stamp;
    unsigned long int updated;
    unsigned char ha[MAX_ADDR_LEN];
  };
""")

HEADERS["netinet/if_ether.h"] = dict(deps=["sys/types.h", "stdint.h", "net/ethernet.h", "net/if_arp.h"], guard="_NETINET_IF_ETHER_H",
    includes=["sys/types.h", "stdint.h", "net/ethernet.h", "net/if_arp.h"], body="""
struct ether_arp {
  struct arphdr ea_hdr;
  uint8_t arp_sha[ETH_ALEN];
  uint8_t arp_spa[4];
  uint8_t arp_tha[ETH_ALEN];
  uint8_t arp_tpa[4];
};
""")

HEADERS["netinet/igmp.h"] = dict(deps=["sys/types.h", "stdint.h", "netinet/in.h"], guard="_NETINET_IGMP_H",
    includes=["sys/types.h", "stdint.h", "netinet/in.h"], body="""
struct igmp {
  uint8_t igmp_type;
  uint8_t igmp_code;
  uint16_t igmp_cksum;
  struct in_addr igmp_group;
};
""")

HEADERS["net/route.h"] = dict(deps=["sys/types.h", "netinet/in.h", "sys/socket.h"], guard="_NET_ROUTE_H",
    includes=["sys/types.h", "stdint.h", "netinet/in.h", "sys/socket.h"], body="""
struct rtentry
  {
    unsigned long int rt_pad1;
    struct sockaddr rt_dst;
    struct sockaddr rt_gateway;
    struct sockaddr rt_genmask;
    unsigned short int rt_flags;
    short int rt_pad2;
    unsigned long int rt_pad3;
    unsigned char rt_tos;
    unsigned char rt_class;
    short int rt_pad4[3];
    short int rt_metric;
    char *rt_dev;
    unsigned long int rt_mtu;
    unsigned long int rt_window;
    unsigned short int rt_irtt;
  };

struct in6_rtmsg
  {
    struct in6_addr rtmsg_dst;
    struct in6_addr rtmsg_src;
    struct in6_addr rtmsg_gateway;
    uint32_t rtmsg_type;
    uint16_t rtmsg_dst_len;
    uint16_t rtmsg_src_len;
    uint32_t rtmsg_metric;
    unsigned long int rtmsg_info;
    uint32_t rtmsg_flags;
    int rtmsg_ifindex;
  };
""")

HEADERS["netinet/icmp6.h"] = dict(deps=["sys/types.h", "stdint.h", "netinet/in.h"], guard="_NETINET_ICMP6_H",
    includes=["stdint.h", "endian.h", "netinet/in.h"], body="""
struct icmp6_filter
  {
    uint32_t icmp6_filt[8];
  };

struct icmp6_hdr
  {
    uint8_t     icmp6_type;
    uint8_t     icmp6_code;
    uint16_t    icmp6_cksum;
    union
      {
	uint32_t  icmp6_un_data32[1];
	uint16_t  icmp6_un_data16[2];
	uint8_t   icmp6_un_data8[4];
      } icmp6_dataun;
  };

struct nd_router_solicit
  {
    struct icmp6_hdr  nd_rs_hdr;
  };

struct nd_router_advert
  {
    struct icmp6_hdr  nd_ra_hdr;
    uint32_t   nd_ra_reachable;
    uint32_t   nd_ra_retransmit;
  };

struct nd_neighbor_solicit
  {
    struct icmp6_hdr  nd_ns_hdr;
    struct in6_addr   nd_ns_target;
  };

struct nd_neighbor_advert
  {
    struct icmp6_hdr  nd_na_hdr;
    struct in6_addr   nd_na_target;
  };

struct nd_redirect
  {
    struct icmp6_hdr  nd_rd_hdr;
    struct in6_addr   nd_rd_target;
    struct in6_addr   nd_rd_dst;
  };

struct nd_opt_hdr
  {
    uint8_t  nd_opt_type;
    uint8_t  nd_opt_len;
  };

struct nd_opt_prefix_info
  {
    uint8_t   nd_opt_pi_type;
    uint8_t   nd_opt_pi_len;
    uint8_t   nd_opt_pi_prefix_len;
    uint8_t   nd_opt_pi_flags_reserved;
    uint32_t  nd_opt_pi_valid_time;
    uint32_t  nd_opt_pi_preferred_time;
    uint32_t  nd_opt_pi_reserved2;
    struct in6_addr  nd_opt_pi_prefix;
  };

struct nd_opt_rd_hdr
  {
    uint8_t   nd_opt_rh_type;
    uint8_t   nd_opt_rh_len;
    uint16_t  nd_opt_rh_reserved1;
    uint32_t  nd_opt_rh_reserved2;
  };

struct nd_opt_mtu
  {
    uint8_t   nd_opt_mtu_type;
    uint8_t   nd_opt_mtu_len;
    uint16_t  nd_opt_mtu_reserved;
    uint32_t  nd_opt_mtu_mtu;
  };

struct mld_hdr
  {
    struct icmp6_hdr    mld_icmp6_hdr;
    struct in6_addr     mld_addr;
  };

struct nd_opt_adv_interval
  {
    uint8_t   nd_opt_adv_interval_type;
    uint8_t   nd_opt_adv_interval_len;
    uint16_t  nd_opt_adv_interval_reserved;
    uint32_t  nd_opt_adv_interval_ival;
  };

struct nd_opt_home_agent_info
  {
    uint8_t   nd_opt_home_agent_info_type;
    uint8_t   nd_opt_home_agent_info_len;
    uint16_t  nd_opt_home_agent_info_reserved;
    uint16_t  nd_opt_home_agent_info_preference;
    uint16_t  nd_opt_home_agent_info_lifetime;
  };
""")

HEADERS["netinet/if_fddi.h"] = dict(deps=["sys/types.h", "stdint.h"], guard="_NETINET_IF_FDDI_H", includes=["sys/types.h", "stdint.h"], body="""
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
""")

HEADERS["arpa/telnet.h"] = dict(deps=[], guard="_ARPA_TELNET_H", includes=[], body="", skip=("TELCMD", "TELOPT", "SLC_NAME", "AUTHTYPE_NAME", "ENCRYPT_NAME", "ENCTYPE_NAME", "STATE_NAME"))


def main():
    for hdr, spec in HEADERS.items():
        text = "/* %s for the Rust libc (generated by tools/gen_net_extra.py: constants and macros copied from the system header's\n   definitions, structs written by hand). */\n" % hdr
        text += "#ifndef %s\n#define %s 1\n#include <features.h>\n" % (spec["guard"], spec["guard"])
        for inc in spec["includes"]:
            text += "#include <%s>\n" % inc
        text += "#ifdef __cplusplus\nextern \"C\" {\n#endif\n"
        text += spec["body"]
        text += consts(hdr, spec["deps"], spec.get("skip", ())) + "\n"
        text += "#ifdef __cplusplus\n}\n#endif\n#endif\n"
        path = os.path.join(ROOT, "include-static", hdr)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        print(hdr, text.count("\n"), "lines")


main()
