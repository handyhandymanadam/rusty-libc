use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
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
        ("SHADOW", V::Txt(r#""/etc/shadow""#)),
    ]),
    Item::Blank,
    Item::Block { head: "struct spwd ", body: &["", "  char *sp_namp;", "  char *sp_pwdp;", "  long int sp_lstchg;", "  long int sp_min;", "  long int sp_max;", "  long int sp_warn;", "  long int sp_inact;", "  long int sp_expire;", "  unsigned long int sp_flag;", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

