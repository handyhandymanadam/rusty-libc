use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_timeval.h",
    items: &[
        Item::Guard { name: "__timeval_defined", value: "1", end: "", items: &[
            Item::Block { head: "struct timeval ", body: &["", "  long tv_sec;", "  long tv_usec;", ""], tail: "" },
        ]},
    ],
};
