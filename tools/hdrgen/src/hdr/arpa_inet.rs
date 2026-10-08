use crate::model::*;

pub static HDR: Header = Header {
    path: "arpa/inet.h",
    items: &[
        Item::Guard { name: "_ARPA_INET_H", value: "1", end: "", items: &[
            Item::Include("<stdint.h>"),
            Item::Include("<netinet/in.h>"),
            Item::Include("<bits/rlibc-net-inet.h>"),
            Item::Gate(&[
                Branch { head: "if __USE_FORTIFY_LEVEL > 0 && defined __fortify_function", items: &[
                    Item::Include("<bits/inet-fortified.h>"),
                ] },
            ], ""),
        ]},
    ],
};
