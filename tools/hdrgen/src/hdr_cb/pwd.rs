use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifndef __uid_t_defined", items: &[
            Item::Typedef("unsigned int", "uid_t"),
            Item::Consts(&[
                ("__uid_t_defined", V::Txt("")),
            ]),
        ] },
    ], ""),
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
        ("NSS_BUFLEN_PASSWD", V::Dec(1024)),
    ]),
    Item::Blank,
    Item::Block { head: "struct passwd ", body: &["", "  char *pw_name;", "  char *pw_passwd;", "  uid_t pw_uid;", "  gid_t pw_gid;", "  char *pw_gecos;", "  char *pw_dir;", "  char *pw_shell;", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

