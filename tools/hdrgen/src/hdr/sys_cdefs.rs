use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/cdefs.h",
    items: &[
        Item::Include("<features.h>"),
    ],
};
