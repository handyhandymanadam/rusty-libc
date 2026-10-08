use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifndef __gid_t_defined", items: &[
            Item::Typedef("unsigned int", "gid_t"),
            Item::Consts(&[
                ("__gid_t_defined", V::Txt("")),
            ]),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifndef __FILE_defined", items: &[
            Item::Raw(Reason::Other, "#include <bits/types/struct_FILE.h>"),
            Item::Typedef("struct _IO_FILE", "FILE"),
            Item::Consts(&[
                ("__FILE_defined", V::Dec(1)),
            ]),
        ] },
    ], ""),
    Item::Blank,
    Item::Consts(&[
        ("NSS_BUFLEN_GROUP", V::Dec(1024)),
    ]),
    Item::Blank,
    Item::Block { head: "struct group ", body: &["", "  char *gr_name;", "  char *gr_passwd;", "  gid_t gr_gid;", "  char **gr_mem;", ""], tail: "" },
    Item::Blank,
    Item::Decl("int setgroups(size_t __n, const gid_t *__groups);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

