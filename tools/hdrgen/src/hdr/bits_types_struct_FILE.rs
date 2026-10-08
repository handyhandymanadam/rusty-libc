use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_FILE.h",
    items: &[
        Item::Guard { name: "_RLIBC_STRUCT_FILE_H", value: "1", end: "", items: &[
            Item::Block { head: "struct _IO_FILE ", body: &["", "  char __rlibc_opaque[216] __attribute__ ((__aligned__ (8)));", ""], tail: "" },
        ]},
    ],
};
