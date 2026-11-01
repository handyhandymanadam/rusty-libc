use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/getopt_posix.h",
    items: &[
        Item::Guard { name: "_GETOPT_POSIX_H", value: "1", end: "", items: &[
            Item::Comment("/* What <unistd.h> pulls in: optarg, optind, opterr, optopt and getopt. */"),
            Item::Include("<bits/getopt_core.h>"),
        ]},
    ],
};
