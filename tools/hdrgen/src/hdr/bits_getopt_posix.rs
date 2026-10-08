use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/getopt_posix.h",
    items: &[
        Item::Guard { name: "_GETOPT_POSIX_H", value: "1", end: "", items: &[
            Item::Include("<bits/getopt_core.h>"),
        ]},
    ],
};
