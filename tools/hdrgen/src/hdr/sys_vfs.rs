use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/vfs.h",
    items: &[
        Item::Include("<sys/statfs.h>"),
    ],
};
