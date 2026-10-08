use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/__sigval_t.h",
    items: &[
        Item::Guard { name: "__sigval_t_defined", value: "1", end: "", items: &[
            Item::Block { head: "union sigval ", body: &["", "  int sival_int;", "  void *sival_ptr;", ""], tail: "" },
            Item::Typedef("union sigval", "__sigval_t"),
        ]},
    ],
};
