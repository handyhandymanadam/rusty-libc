use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/byteswap.h",
    items: &[
        Item::Guard { name: "_BITS_BYTESWAP_H", value: "1", end: "", items: &[
            Item::Include("<stdint.h>"),
            Item::Raw(Reason::GlibcMacro, "#define __bswap_constant_16(x) ((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))"),
            Item::Raw(Reason::GlibcMacro, "#define __bswap_constant_32(x) __builtin_bswap32 (x)"),
            Item::Raw(Reason::GlibcMacro, "#define __bswap_constant_64(x) __builtin_bswap64 (x)"),
            Item::Raw(Reason::StaticInline, "static __inline uint16_t __bswap_16 (uint16_t __bsx) { return __builtin_bswap16 (__bsx); }"),
            Item::Raw(Reason::StaticInline, "static __inline uint32_t __bswap_32 (uint32_t __bsx) { return __builtin_bswap32 (__bsx); }"),
            Item::Raw(Reason::StaticInline, "static __inline uint64_t __bswap_64 (uint64_t __bsx) { return __builtin_bswap64 (__bsx); }"),
        ]},
    ],
};
