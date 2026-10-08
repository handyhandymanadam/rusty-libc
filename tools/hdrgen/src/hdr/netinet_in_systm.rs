use crate::model::*;

pub static HDR: Header = Header {
    path: "netinet/in_systm.h",
    items: &[
        Item::Guard { name: "_NETINET_IN_SYSTM_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Include("<stdint.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Typedef("uint16_t", "n_short"),
            Item::Typedef("uint32_t", "n_long"),
            Item::Typedef("uint32_t", "n_time"),
            Item::Blank,
            Item::ExternEnd,
        ]},
    ],
};
