use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/stack_t.h",
    items: &[
        Item::Guard { name: "__stack_t_defined", value: "1", end: "", items: &[
            Item::Include("<stddef.h>"),
            Item::Block { head: "typedef struct ", body: &["", "  void *ss_sp;", "  int ss_flags;", "  size_t ss_size;", ""], tail: " stack_t" },
        ]},
    ],
};
