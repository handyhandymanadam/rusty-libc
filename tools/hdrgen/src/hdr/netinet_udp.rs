use crate::model::*;

pub static HDR: Header = Header {
    path: "netinet/udp.h",
    items: &[
        Item::Guard { name: "_NETINET_UDP_H", value: "1", end: "", items: &[
            Item::Include("<stdint.h>"),
            Item::Blank,
            Item::Consts(&[
                ("SOL_UDP", V::Dec(17)),
                ("UDP_CORK", V::Dec(1)),
                ("UDP_ENCAP", V::Dec(100)),
                ("UDP_ENCAP_ESPINUDP", V::Dec(2)),
                ("UDP_ENCAP_ESPINUDP_NON_IKE", V::Dec(1)),
                ("UDP_ENCAP_GTP0", V::Dec(4)),
                ("UDP_ENCAP_GTP1U", V::Dec(5)),
                ("UDP_ENCAP_L2TPINUDP", V::Dec(3)),
                ("UDP_GRO", V::Dec(104)),
                ("UDP_NO_CHECK6_RX", V::Dec(102)),
                ("UDP_NO_CHECK6_TX", V::Dec(101)),
                ("UDP_SEGMENT", V::Dec(103)),
            ]),
            Item::Blank,
            Item::Block { head: "struct udphdr ", body: &["", "  __extension__ union {", "    struct {", "      uint16_t uh_sport;", "      uint16_t uh_dport;", "      uint16_t uh_ulen;", "      uint16_t uh_sum;", "    };", "    struct {", "      uint16_t source;", "      uint16_t dest;", "      uint16_t len;", "      uint16_t check;", "    };", "  };", ""], tail: "" },
            Item::Blank,
        ]},
    ],
};
