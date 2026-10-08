use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_timespec.h",
    items: &[
        Item::Guard { name: "__timespec_defined", value: "1", end: "", items: &[
            Item::Block { head: "struct timespec ", body: &["", "  long tv_sec;", "  long tv_nsec;", ""], tail: "" },
        ]},
    ],
};
