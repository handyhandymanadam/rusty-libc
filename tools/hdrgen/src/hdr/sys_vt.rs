use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/vt.h",
    items: &[
        Item::Include("<linux/vt.h>"),
    ],
};
