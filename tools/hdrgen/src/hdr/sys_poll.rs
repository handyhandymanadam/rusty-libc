use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/poll.h",
    items: &[
        Item::Include("<poll.h>"),
    ],
};
