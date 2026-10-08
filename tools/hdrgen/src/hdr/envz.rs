use crate::model::*;

pub static HDR: Header = Header {
    path: "envz.h",
    items: &[
        Item::Guard { name: "_RLIBC_ENVZ_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<argz.h>"),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-envzcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
