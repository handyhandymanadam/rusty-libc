use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/single_threaded.h",
    items: &[
        Item::Guard { name: "_SYS_SINGLE_THREADED_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Decl("extern char __libc_single_threaded;"),
            Item::ExternEnd,
        ]},
    ],
};
