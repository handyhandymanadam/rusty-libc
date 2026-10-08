use crate::model::*;

pub static HDR: Header = Header {
    path: "ifaddrs.h",
    items: &[
        Item::Guard { name: "_IFADDRS_H", value: "1", end: "", items: &[
            Item::Include("<sys/socket.h>"),
            Item::Blank,
            Item::Block { head: "struct ifaddrs ", body: &["", "  struct ifaddrs *ifa_next;", "  char *ifa_name;", "  unsigned int ifa_flags;", "  struct sockaddr *ifa_addr;", "  struct sockaddr *ifa_netmask;", "  union {", "    struct sockaddr *ifu_broadaddr;", "    struct sockaddr *ifu_dstaddr;", "  } ifa_ifu;", "  void *ifa_data;", ""], tail: "" },
            Item::Consts(&[
                ("ifa_broadaddr", V::Txt("ifa_ifu.ifu_broadaddr")),
                ("ifa_dstaddr", V::Txt("ifa_ifu.ifu_dstaddr")),
            ]),
            Item::Blank,
            Item::Include("<bits/rlibc-net-ifaddrs.h>"),
        ]},
    ],
};
