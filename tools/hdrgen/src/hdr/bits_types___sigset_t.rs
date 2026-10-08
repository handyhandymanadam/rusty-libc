use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/__sigset_t.h",
    items: &[
        Item::Guard { name: "____sigset_t_defined", value: "", end: "", items: &[
            Item::Block { head: "typedef struct ", body: &["", "  unsigned long __val[16];", ""], tail: " __sigset_t" },
        ]},
    ],
};
