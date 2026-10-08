use crate::model::*;

pub static HDR: Header = Header {
    path: "netinet/if_ether.h",
    items: &[
        Item::Guard { name: "_NETINET_IF_ETHER_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<stdint.h>"),
            Item::Include("<net/ethernet.h>"),
            Item::Include("<net/if_arp.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct ether_arp ", body: &["", "  struct arphdr ea_hdr;", "  uint8_t arp_sha[ETH_ALEN];", "  uint8_t arp_spa[4];", "  uint8_t arp_tha[ETH_ALEN];", "  uint8_t arp_tpa[4];", ""], tail: "" },
            Item::Raw(Reason::GlibcMacro, "#define ETHER_MAP_IP_MULTICAST(ipaddr,enaddr) { (enaddr)[0] = 0x01; (enaddr)[1] = 0x00; (enaddr)[2] = 0x5e; (enaddr)[3] = ((uint8_t *)ipaddr)[1] & 0x7f; (enaddr)[4] = ((uint8_t *)ipaddr)[2]; (enaddr)[5] = ((uint8_t *)ipaddr)[3]; }"),
            Item::Consts(&[
                ("arp_hln", V::Txt("ea_hdr.ar_hln")),
                ("arp_hrd", V::Txt("ea_hdr.ar_hrd")),
                ("arp_op", V::Txt("ea_hdr.ar_op")),
                ("arp_pln", V::Txt("ea_hdr.ar_pln")),
                ("arp_pro", V::Txt("ea_hdr.ar_pro")),
            ]),
            Item::ExternEnd,
        ]},
    ],
};
