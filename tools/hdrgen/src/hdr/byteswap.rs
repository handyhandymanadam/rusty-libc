use crate::model::*;

pub static HDR: Header = Header {
    path: "byteswap.h",
    items: &[
        Item::Guard { name: "_BYTESWAP_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Include("<bits/byteswap.h>"),
            Item::Raw(Reason::GlibcMacro, "#define bswap_16(x) __bswap_16 (x)"),
            Item::Raw(Reason::GlibcMacro, "#define bswap_32(x) __bswap_32 (x)"),
            Item::Raw(Reason::GlibcMacro, "#define bswap_64(x) __bswap_64 (x)"),
        ]},
    ],
};
