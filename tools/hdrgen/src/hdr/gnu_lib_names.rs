use crate::model::*;

pub static HDR: Header = Header {
    path: "gnu/lib-names.h",
    items: &[
        Item::Guard { name: "__GNU_LIB_NAMES_H", value: "1", end: "", items: &[
            Item::Include("<gnu/lib-names-64.h>"),
        ]},
    ],
};
