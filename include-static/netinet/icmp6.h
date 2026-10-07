#ifndef _NETINET_ICMP6_H
#define _NETINET_ICMP6_H 1
#include <features.h>
#include <stdint.h>
#include <endian.h>
#include <netinet/in.h>
#ifdef __cplusplus
extern "C" {
#endif

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
#define ICMP6_DST_UNREACH 1
#define ICMP6_DST_UNREACH_ADDR 3
#define ICMP6_DST_UNREACH_ADMIN 1
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#define ICMP6_DST_UNREACH_NOPORT 4
#define ICMP6_DST_UNREACH_NOROUTE 0
#define ICMP6_ECHO_REPLY 129
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_FILTER 1
#define ICMP6_FILTER_BLOCK 1
#define ICMP6_FILTER_BLOCKOTHERS 3
#define ICMP6_FILTER_PASS 2
#define ICMP6_FILTER_PASSONLY 4
#define ICMP6_FILTER_SETBLOCK(type,filterp) ((((filterp)->icmp6_filt[(type) >> 5]) |= (1U << ((type) & 31))))
#define ICMP6_FILTER_SETBLOCKALL(filterp) memset (filterp, 0xFF, sizeof (struct icmp6_filter));
#define ICMP6_FILTER_SETPASS(type,filterp) ((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1U << ((type) & 31))))
#define ICMP6_FILTER_SETPASSALL(filterp) memset (filterp, 0, sizeof (struct icmp6_filter));
#define ICMP6_FILTER_WILLBLOCK(type,filterp) ((((filterp)->icmp6_filt[(type) >> 5]) & (1U << ((type) & 31))) != 0)
#define ICMP6_FILTER_WILLPASS(type,filterp) ((((filterp)->icmp6_filt[(type) >> 5]) & (1U << ((type) & 31))) == 0)
#define ICMP6_INFOMSG_MASK 0x80
#define ICMP6_PACKET_TOO_BIG 2
#define ICMP6_PARAMPROB_HEADER 0
#define ICMP6_PARAMPROB_NEXTHEADER 1
#define ICMP6_PARAMPROB_OPTION 2
#define ICMP6_PARAM_PROB 4
#define ICMP6_ROUTER_RENUMBERING 138
#define ICMP6_RR_FLAGS_FORCEAPPLY 0x20
#define ICMP6_RR_FLAGS_PREVDONE 0x08
#define ICMP6_RR_FLAGS_REQRESULT 0x40
#define ICMP6_RR_FLAGS_SPECSITE 0x10
#define ICMP6_RR_FLAGS_TEST 0x80
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME 0x40
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME 0x80
#define ICMP6_RR_PCOUSE_RAFLAGS_AUTO 0x10
#define ICMP6_RR_PCOUSE_RAFLAGS_ONLINK 0x20
#define ICMP6_RR_RESULT_FLAGS_FORBIDDEN 0x0100
#define ICMP6_RR_RESULT_FLAGS_OOB 0x0200
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_TIME_EXCEED_REASSEMBLY 1
#define ICMP6_TIME_EXCEED_TRANSIT 0
#define ICMPV6_EXT_ECHO_REPLY 161
#define ICMPV6_EXT_ECHO_REQUEST 160
#define MLD_LISTENER_QUERY 130
#define MLD_LISTENER_REDUCTION 132
#define MLD_LISTENER_REPORT 131
#define ND_NA_FLAG_OVERRIDE 0x00000020
#define ND_NA_FLAG_ROUTER 0x00000080
#define ND_NA_FLAG_SOLICITED 0x00000040
#define ND_NEIGHBOR_ADVERT 136
#define ND_NEIGHBOR_SOLICIT 135
#define ND_OPT_HOME_AGENT_INFO 8
#define ND_OPT_MTU 5
#define ND_OPT_PI_FLAG_AUTO 0x40
#define ND_OPT_PI_FLAG_ONLINK 0x80
#define ND_OPT_PI_FLAG_RADDR 0x20
#define ND_OPT_PREFIX_INFORMATION 3
#define ND_OPT_REDIRECTED_HEADER 4
#define ND_OPT_RTR_ADV_INTERVAL 7
#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_TARGET_LINKADDR 2
#define ND_RA_FLAG_HOME_AGENT 0x20
#define ND_RA_FLAG_MANAGED 0x80
#define ND_RA_FLAG_OTHER 0x40
#define ND_REDIRECT 137
#define ND_ROUTER_ADVERT 134
#define ND_ROUTER_SOLICIT 133
#define PRIB16 "hB"
#define PRIB32 "B"
#define PRIB64 __PRI64_PREFIX "B"
#define PRIB8 "hhB"
#define PRIBFAST16 __PRIPTR_PREFIX "B"
#define PRIBFAST32 __PRIPTR_PREFIX "B"
#define PRIBFAST64 __PRI64_PREFIX "B"
#define PRIBFAST8 "hhB"
#define PRIBLEAST16 "hB"
#define PRIBLEAST32 "B"
#define PRIBLEAST64 __PRI64_PREFIX "B"
#define PRIBLEAST8 "hhB"
#define PRIBMAX __PRI64_PREFIX "B"
#define PRIBPTR __PRIPTR_PREFIX "B"
#define PRIX16 "hX"
#define PRIX32 "X"
#define PRIX64 __PRI64_PREFIX "X"
#define PRIX8 "hhX"
#define PRIXFAST16 __PRIPTR_PREFIX "X"
#define PRIXFAST32 __PRIPTR_PREFIX "X"
#define PRIXFAST64 __PRI64_PREFIX "X"
#define PRIXFAST8 "hhX"
#define PRIXLEAST16 "hX"
#define PRIXLEAST32 "X"
#define PRIXLEAST64 __PRI64_PREFIX "X"
#define PRIXLEAST8 "hhX"
#define PRIXMAX __PRI64_PREFIX "X"
#define PRIXPTR __PRIPTR_PREFIX "X"
#define PRIb16 "hb"
#define PRIb32 "b"
#define PRIb64 __PRI64_PREFIX "b"
#define PRIb8 "hhb"
#define PRIbFAST16 __PRIPTR_PREFIX "b"
#define PRIbFAST32 __PRIPTR_PREFIX "b"
#define PRIbFAST64 __PRI64_PREFIX "b"
#define PRIbFAST8 "hhb"
#define PRIbLEAST16 "hb"
#define PRIbLEAST32 "b"
#define PRIbLEAST64 __PRI64_PREFIX "b"
#define PRIbLEAST8 "hhb"
#define PRIbMAX __PRI64_PREFIX "b"
#define PRIbPTR __PRIPTR_PREFIX "b"
#define PRId16 "hd"
#define PRId32 "d"
#define PRId64 __PRI64_PREFIX "d"
#define PRId8 "hhd"
#define PRIdFAST16 __PRIPTR_PREFIX "d"
#define PRIdFAST32 __PRIPTR_PREFIX "d"
#define PRIdFAST64 __PRI64_PREFIX "d"
#define PRIdFAST8 "hhd"
#define PRIdLEAST16 "hd"
#define PRIdLEAST32 "d"
#define PRIdLEAST64 __PRI64_PREFIX "d"
#define PRIdLEAST8 "hhd"
#define PRIdMAX __PRI64_PREFIX "d"
#define PRIdPTR __PRIPTR_PREFIX "d"
#define PRIi16 "hi"
#define PRIi32 "i"
#define PRIi64 __PRI64_PREFIX "i"
#define PRIi8 "hhi"
#define PRIiFAST16 __PRIPTR_PREFIX "i"
#define PRIiFAST32 __PRIPTR_PREFIX "i"
#define PRIiFAST64 __PRI64_PREFIX "i"
#define PRIiFAST8 "hhi"
#define PRIiLEAST16 "hi"
#define PRIiLEAST32 "i"
#define PRIiLEAST64 __PRI64_PREFIX "i"
#define PRIiLEAST8 "hhi"
#define PRIiMAX __PRI64_PREFIX "i"
#define PRIiPTR __PRIPTR_PREFIX "i"
#define PRIo16 "ho"
#define PRIo32 "o"
#define PRIo64 __PRI64_PREFIX "o"
#define PRIo8 "hho"
#define PRIoFAST16 __PRIPTR_PREFIX "o"
#define PRIoFAST32 __PRIPTR_PREFIX "o"
#define PRIoFAST64 __PRI64_PREFIX "o"
#define PRIoFAST8 "hho"
#define PRIoLEAST16 "ho"
#define PRIoLEAST32 "o"
#define PRIoLEAST64 __PRI64_PREFIX "o"
#define PRIoLEAST8 "hho"
#define PRIoMAX __PRI64_PREFIX "o"
#define PRIoPTR __PRIPTR_PREFIX "o"
#define PRIu16 "hu"
#define PRIu32 "u"
#define PRIu64 __PRI64_PREFIX "u"
#define PRIu8 "hhu"
#define PRIuFAST16 __PRIPTR_PREFIX "u"
#define PRIuFAST32 __PRIPTR_PREFIX "u"
#define PRIuFAST64 __PRI64_PREFIX "u"
#define PRIuFAST8 "hhu"
#define PRIuLEAST16 "hu"
#define PRIuLEAST32 "u"
#define PRIuLEAST64 __PRI64_PREFIX "u"
#define PRIuLEAST8 "hhu"
#define PRIuMAX __PRI64_PREFIX "u"
#define PRIuPTR __PRIPTR_PREFIX "u"
#define PRIx16 "hx"
#define PRIx32 "x"
#define PRIx64 __PRI64_PREFIX "x"
#define PRIx8 "hhx"
#define PRIxFAST16 __PRIPTR_PREFIX "x"
#define PRIxFAST32 __PRIPTR_PREFIX "x"
#define PRIxFAST64 __PRI64_PREFIX "x"
#define PRIxFAST8 "hhx"
#define PRIxLEAST16 "hx"
#define PRIxLEAST32 "x"
#define PRIxLEAST64 __PRI64_PREFIX "x"
#define PRIxLEAST8 "hhx"
#define PRIxMAX __PRI64_PREFIX "x"
#define PRIxPTR __PRIPTR_PREFIX "x"
#define RPM_PCO_ADD 1
#define RPM_PCO_CHANGE 2
#define RPM_PCO_SETGLOBAL 3
#define SCNb16 "hb"
#define SCNb32 "b"
#define SCNb64 __PRI64_PREFIX "b"
#define SCNb8 "hhb"
#define SCNbFAST16 __PRIPTR_PREFIX "b"
#define SCNbFAST32 __PRIPTR_PREFIX "b"
#define SCNbFAST64 __PRI64_PREFIX "b"
#define SCNbFAST8 "hhb"
#define SCNbLEAST16 "hb"
#define SCNbLEAST32 "b"
#define SCNbLEAST64 __PRI64_PREFIX "b"
#define SCNbLEAST8 "hhb"
#define SCNbMAX __PRI64_PREFIX "b"
#define SCNbPTR __PRIPTR_PREFIX "b"
#define SCNd16 "hd"
#define SCNd32 "d"
#define SCNd64 __PRI64_PREFIX "d"
#define SCNd8 "hhd"
#define SCNdFAST16 __PRIPTR_PREFIX "d"
#define SCNdFAST32 __PRIPTR_PREFIX "d"
#define SCNdFAST64 __PRI64_PREFIX "d"
#define SCNdFAST8 "hhd"
#define SCNdLEAST16 "hd"
#define SCNdLEAST32 "d"
#define SCNdLEAST64 __PRI64_PREFIX "d"
#define SCNdLEAST8 "hhd"
#define SCNdMAX __PRI64_PREFIX "d"
#define SCNdPTR __PRIPTR_PREFIX "d"
#define SCNi16 "hi"
#define SCNi32 "i"
#define SCNi64 __PRI64_PREFIX "i"
#define SCNi8 "hhi"
#define SCNiFAST16 __PRIPTR_PREFIX "i"
#define SCNiFAST32 __PRIPTR_PREFIX "i"
#define SCNiFAST64 __PRI64_PREFIX "i"
#define SCNiFAST8 "hhi"
#define SCNiLEAST16 "hi"
#define SCNiLEAST32 "i"
#define SCNiLEAST64 __PRI64_PREFIX "i"
#define SCNiLEAST8 "hhi"
#define SCNiMAX __PRI64_PREFIX "i"
#define SCNiPTR __PRIPTR_PREFIX "i"
#define SCNo16 "ho"
#define SCNo32 "o"
#define SCNo64 __PRI64_PREFIX "o"
#define SCNo8 "hho"
#define SCNoFAST16 __PRIPTR_PREFIX "o"
#define SCNoFAST32 __PRIPTR_PREFIX "o"
#define SCNoFAST64 __PRI64_PREFIX "o"
#define SCNoFAST8 "hho"
#define SCNoLEAST16 "ho"
#define SCNoLEAST32 "o"
#define SCNoLEAST64 __PRI64_PREFIX "o"
#define SCNoLEAST8 "hho"
#define SCNoMAX __PRI64_PREFIX "o"
#define SCNoPTR __PRIPTR_PREFIX "o"
#define SCNu16 "hu"
#define SCNu32 "u"
#define SCNu64 __PRI64_PREFIX "u"
#define SCNu8 "hhu"
#define SCNuFAST16 __PRIPTR_PREFIX "u"
#define SCNuFAST32 __PRIPTR_PREFIX "u"
#define SCNuFAST64 __PRI64_PREFIX "u"
#define SCNuFAST8 "hhu"
#define SCNuLEAST16 "hu"
#define SCNuLEAST32 "u"
#define SCNuLEAST64 __PRI64_PREFIX "u"
#define SCNuLEAST8 "hhu"
#define SCNuMAX __PRI64_PREFIX "u"
#define SCNuPTR __PRIPTR_PREFIX "u"
#define SCNx16 "hx"
#define SCNx32 "x"
#define SCNx64 __PRI64_PREFIX "x"
#define SCNx8 "hhx"
#define SCNxFAST16 __PRIPTR_PREFIX "x"
#define SCNxFAST32 __PRIPTR_PREFIX "x"
#define SCNxFAST64 __PRI64_PREFIX "x"
#define SCNxFAST8 "hhx"
#define SCNxLEAST16 "hx"
#define SCNxLEAST32 "x"
#define SCNxLEAST64 __PRI64_PREFIX "x"
#define SCNxLEAST8 "hhx"
#define SCNxMAX __PRI64_PREFIX "x"
#define SCNxPTR __PRIPTR_PREFIX "x"
#define icmp6_data16 icmp6_dataun.icmp6_un_data16
#define icmp6_data32 icmp6_dataun.icmp6_un_data32
#define icmp6_data8 icmp6_dataun.icmp6_un_data8
#define icmp6_id icmp6_data16[0]
#define icmp6_maxdelay icmp6_data16[0]
#define icmp6_mtu icmp6_data32[0]
#define icmp6_pptr icmp6_data32[0]
#define icmp6_seq icmp6_data16[1]
#define mld_cksum mld_icmp6_hdr.icmp6_cksum
#define mld_code mld_icmp6_hdr.icmp6_code
#define mld_maxdelay mld_icmp6_hdr.icmp6_data16[0]
#define mld_reserved mld_icmp6_hdr.icmp6_data16[1]
#define mld_type mld_icmp6_hdr.icmp6_type
#define nd_na_cksum nd_na_hdr.icmp6_cksum
#define nd_na_code nd_na_hdr.icmp6_code
#define nd_na_flags_reserved nd_na_hdr.icmp6_data32[0]
#define nd_na_type nd_na_hdr.icmp6_type
#define nd_ns_cksum nd_ns_hdr.icmp6_cksum
#define nd_ns_code nd_ns_hdr.icmp6_code
#define nd_ns_reserved nd_ns_hdr.icmp6_data32[0]
#define nd_ns_type nd_ns_hdr.icmp6_type
#define nd_ra_cksum nd_ra_hdr.icmp6_cksum
#define nd_ra_code nd_ra_hdr.icmp6_code
#define nd_ra_curhoplimit nd_ra_hdr.icmp6_data8[0]
#define nd_ra_flags_reserved nd_ra_hdr.icmp6_data8[1]
#define nd_ra_router_lifetime nd_ra_hdr.icmp6_data16[1]
#define nd_ra_type nd_ra_hdr.icmp6_type
#define nd_rd_cksum nd_rd_hdr.icmp6_cksum
#define nd_rd_code nd_rd_hdr.icmp6_code
#define nd_rd_reserved nd_rd_hdr.icmp6_data32[0]
#define nd_rd_type nd_rd_hdr.icmp6_type
#define nd_rs_cksum nd_rs_hdr.icmp6_cksum
#define nd_rs_code nd_rs_hdr.icmp6_code
#define nd_rs_reserved nd_rs_hdr.icmp6_data32[0]
#define nd_rs_type nd_rs_hdr.icmp6_type
#define rr_cksum rr_hdr.icmp6_cksum
#define rr_code rr_hdr.icmp6_code
#define rr_seqnum rr_hdr.icmp6_data32[0]
#define rr_type rr_hdr.icmp6_type
#ifdef __cplusplus
}
#endif
#endif
