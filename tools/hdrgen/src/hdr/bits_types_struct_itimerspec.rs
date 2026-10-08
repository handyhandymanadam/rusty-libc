use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_itimerspec.h",
    items: &[
        Item::Guard { name: "__itimerspec_defined", value: "1", end: "", items: &[
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Block { head: "struct itimerspec ", body: &["", "  struct timespec it_interval;", "  struct timespec it_value;", ""], tail: "" },
        ]},
    ],
};
