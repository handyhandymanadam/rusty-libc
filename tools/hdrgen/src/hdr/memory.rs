use crate::model::*;

pub static HDR: Header = Header {
    path: "memory.h",
    items: &[
        Item::Guard { name: "_MEMORY_H", value: "1", end: "", items: &[
            Item::Include("<string.h>"),
        ]},
    ],
};
