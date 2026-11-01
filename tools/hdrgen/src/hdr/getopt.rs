use crate::model::*;

pub static HDR: Header = Header {
    path: "getopt.h",
    items: &[
        Item::Guard { name: "_GETOPT_H", value: "1", end: "", items: &[
            Item::Comment("/* getopt.h as glibc splits it: the POSIX part (also in <unistd.h>) and the GNU long-option part. */"),
            Item::Include("<bits/getopt_core.h>"),
            Item::Include("<bits/getopt_ext.h>"),
        ]},
    ],
};
