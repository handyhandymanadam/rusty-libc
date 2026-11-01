use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu/lib-names.h",
    items: &[
        Item::Comment("/* gnu/lib-names.h: LIBC_SO, LIBM_SO, LD_SO, ... for the program's ABI (x86-64 only here) */"),
        Item::Guard { name: "__GNU_LIB_NAMES_H", value: "1", end: "", items: &[
            Item::Include("<gnu/lib-names-64.h>"),
        ]},
    ],
};
