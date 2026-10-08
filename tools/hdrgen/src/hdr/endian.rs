use crate::model::*;

pub static HDR: Header = Header {
    path: "endian.h",
    items: &[
        Item::Guard { name: "_ENDIAN_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Include("<bits/endian.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __USE_MISC", items: &[
                    Item::Consts(&[
                        ("LITTLE_ENDIAN", V::Txt("__LITTLE_ENDIAN")),
                        ("BIG_ENDIAN", V::Txt("__BIG_ENDIAN")),
                        ("PDP_ENDIAN", V::Txt("__PDP_ENDIAN")),
                        ("BYTE_ORDER", V::Txt("__BYTE_ORDER")),
                    ]),
                ] },
            ], ""),
            Item::Include("<bits/byteswap.h>"),
            Item::Include("<bits/uintn-identity.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __USE_MISC", items: &[
                    Item::Raw(Reason::GlibcMacro, "# define htobe16(x) __bswap_16 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define htole16(x) __uint16_identity (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define be16toh(x) __bswap_16 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define le16toh(x) __uint16_identity (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define htobe32(x) __bswap_32 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define htole32(x) __uint32_identity (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define be32toh(x) __bswap_32 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define le32toh(x) __uint32_identity (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define htobe64(x) __bswap_64 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define htole64(x) __uint64_identity (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define be64toh(x) __bswap_64 (x)"),
                    Item::Raw(Reason::GlibcMacro, "# define le64toh(x) __uint64_identity (x)"),
                ] },
            ], ""),
        ]},
    ],
};
