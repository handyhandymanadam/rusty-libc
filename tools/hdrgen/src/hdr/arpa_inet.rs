use crate::model::*;

pub static HDR: Header = Header {
    path: "arpa/inet.h",
    items: &[
        Item::Guard { name: "_ARPA_INET_H", value: "1", end: "", items: &[
            Item::Include("<stdint.h>"),
            Item::Include("<netinet/in.h>"),
            Item::Include("<bits/rlibc-net-inet.h>"),
        ]},
    ],
};
