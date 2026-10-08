use crate::model::*;

pub static HDR: Header = Header {
    path: "syslog.h",
    items: &[
        Item::Include("<sys/syslog.h>"),
    ],
};
