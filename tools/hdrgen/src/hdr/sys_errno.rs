use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/errno.h",
    items: &[
        Item::Include("<errno.h>"),
    ],
};
