use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/sockaddr.h",
    items: &[
        Item::Guard { name: "_RLIBC_BITS_SOCKADDR_H", value: "1", end: "", items: &[
            Item::Typedef("unsigned short int", "__sa_family_t"),
            Item::Raw(Reason::GlibcMacro, "#define __SOCKADDR_COMMON(sa_prefix) __sa_family_t sa_prefix##family"),
            Item::Consts(&[
                ("__SOCKADDR_COMMON_SIZE", V::Txt("(sizeof (unsigned short int))")),
            ]),
        ]},
    ],
};
