use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_sigstack.h",
    items: &[
        Item::Guard { name: "__sigstack_defined", value: "1", end: "", items: &[
            Item::Block { head: "struct sigstack ", body: &["", "  void *ss_sp;", "  int ss_onstack;", ""], tail: "" },
        ]},
    ],
};
