use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/fcntl.h",
    items: &[
        Item::Include("<fcntl.h>"),
    ],
};
