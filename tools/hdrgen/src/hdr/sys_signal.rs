use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/signal.h",
    items: &[
        Item::Include("<signal.h>"),
    ],
};
