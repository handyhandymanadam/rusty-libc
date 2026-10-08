use crate::model::*;

pub static HDR: Header = Header {
    path: "getopt.h",
    items: &[
        Item::Guard { name: "_GETOPT_H", value: "1", end: "", items: &[
            Item::Include("<bits/getopt_core.h>"),
            Item::Include("<bits/getopt_ext.h>"),
        ]},
    ],
};
