use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Comment("/* written by hand: types, unions, macros with arguments */"),
    Item::Gate(&[
        Branch { head: "ifndef __fsword_t_defined", items: &[
            Item::ConstsFlat(&[
                ("__fsword_t_defined", V::Dec(1)),
            ]),
            Item::Decl("typedef long __fsword_t; /* the type of the f_type and f_bsize fields (glibc's bits/types.h) */"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifndef __fsid_t_defined", items: &[
            Item::ConstsFlat(&[
                ("__fsid_t_defined", V::Dec(1)),
            ]),
            Item::Block { head: "typedef struct ", body: &["", "  int __val[2];", ""], tail: " fsid_t" },
        ] },
    ], ""),
    Item::Block { head: "struct statfs64 ", body: &["", "  long f_type;", "  long f_bsize;", "  uint64_t f_blocks;", "  uint64_t f_bfree;", "  uint64_t f_bavail;", "  uint64_t f_files;", "  uint64_t f_ffree;", "  fsid_t f_fsid;", "  long f_namelen;", "  long f_frsize;", "  long f_flags;", "  long f_spare[4];", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

