use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/sockaddr.h",
    items: &[
        Item::Comment("/* The address-family field every socket address structure starts with. */"),
        Item::Guard { name: "_RLIBC_BITS_SOCKADDR_H", value: "1", end: "", items: &[
            Item::Typedef("unsigned short int", "__sa_family_t"),
            Item::Comment("/* the family field, named with the structure's prefix (sa_family, sin_family, ...) */"),
            Item::Raw(Reason::GlibcMacro, "#define __SOCKADDR_COMMON(sa_prefix) __sa_family_t sa_prefix##family"),
            Item::Consts(&[
                ("__SOCKADDR_COMMON_SIZE", V::Txt("(sizeof (unsigned short int))")),
            ]),
        ]},
    ],
};
