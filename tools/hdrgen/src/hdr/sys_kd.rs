use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/kd.h",
    items: &[
        Item::Include("<linux/kd.h>"),
    ],
};
