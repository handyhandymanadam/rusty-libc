use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/uintn-identity.h",
    items: &[
        Item::Guard { name: "_BITS_UINTN_IDENTITY_H", value: "1", end: "", items: &[
            Item::Include("<stdint.h>"),
            Item::Raw(Reason::StaticInline, "static __inline uint16_t __uint16_identity (uint16_t __x) { return __x; }"),
            Item::Raw(Reason::StaticInline, "static __inline uint32_t __uint32_identity (uint32_t __x) { return __x; }"),
            Item::Raw(Reason::StaticInline, "static __inline uint64_t __uint64_identity (uint64_t __x) { return __x; }"),
        ]},
    ],
};
