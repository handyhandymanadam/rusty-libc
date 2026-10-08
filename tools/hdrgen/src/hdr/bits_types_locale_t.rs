use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/locale_t.h",
    items: &[
        Item::Guard { name: "_BITS_TYPES_LOCALE_T_H", value: "1", end: "", items: &[
            Item::Include("<bits/types/__locale_t.h>"),
            Item::Blank,
            Item::Typedef("__locale_t", "locale_t"),
        ]},
    ],
};
