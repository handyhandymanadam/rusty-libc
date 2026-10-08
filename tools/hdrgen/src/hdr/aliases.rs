use crate::model::*;

pub static HDR: Header = Header {
    path: "aliases.h",
    items: &[
        Item::Guard { name: "_ALIASES_H", value: "1", end: "", items: &[
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::Block { head: "struct aliasent ", body: &["", "  char *alias_name;", "  size_t alias_members_len;", "  char **alias_members;", "  int alias_local;", ""], tail: "" },
            Item::Blank,
            Item::Include("<bits/rlibc-net-aliases.h>"),
        ]},
    ],
};
