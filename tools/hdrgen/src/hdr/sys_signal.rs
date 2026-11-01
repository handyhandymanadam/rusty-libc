use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/signal.h",
    items: &[
        Item::Comment("/* sys/signal.h: the BSD name of signal.h */"),
        Item::Include("<signal.h>"),
    ],
};
