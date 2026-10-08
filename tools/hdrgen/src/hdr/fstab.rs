use crate::model::*;

pub static HDR: Header = Header {
    path: "fstab.h",
    items: &[
        Item::Guard { name: "_RLIBC_FSTAB_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Blank,
            Item::Consts(&[
                ("_PATH_FSTAB", V::Txt(r#""/etc/fstab""#)),
                ("FSTAB", V::Txt(r#""/etc/fstab""#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("FSTAB_RW", V::Txt(r#""rw""#)),
                ("FSTAB_RQ", V::Txt(r#""rq""#)),
                ("FSTAB_RO", V::Txt(r#""ro""#)),
                ("FSTAB_SW", V::Txt(r#""sw""#)),
                ("FSTAB_XX", V::Txt(r#""xx""#)),
            ]),
            Item::Blank,
            Item::Block { head: "struct fstab ", body: &["", "  char *fs_spec;", "  char *fs_file;", "  char *fs_vfstype;", "  char *fs_mntops;", "  const char *fs_type;", "  int fs_freq;", "  int fs_passno;", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-fstabcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
