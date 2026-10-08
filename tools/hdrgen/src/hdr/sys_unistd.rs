use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/unistd.h",
    items: &[
        Item::Include("<unistd.h>"),
    ],
};
