use crate::model::*;

pub static HDR: Header = Header {
    path: "netinet/ether.h",
    items: &[
        Item::Guard { name: "_NETINET_ETHER_H", value: "1", end: "", items: &[
            Item::Include("<net/ethernet.h>"),
            Item::Include("<netinet/if_ether.h>"),
            Item::Blank,
            Item::Include("<bits/rlibc-net-ether.h>"),
        ]},
    ],
};
