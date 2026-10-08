use crate::model::*;

pub static HDR: Header = Header {
    path: "mntent.h",
    items: &[
        Item::Guard { name: "_RLIBC_MNTENT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<stdio.h>"),
            Item::Include("<paths.h>"),
            Item::Blank,
            Item::Consts(&[
                ("MNTTAB", V::Txt("_PATH_MNTTAB")),
                ("MOUNTED", V::Txt("_PATH_MOUNTED")),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("MNTTYPE_IGNORE", V::Txt(r#""ignore""#)),
                ("MNTTYPE_NFS", V::Txt(r#""nfs""#)),
                ("MNTTYPE_SWAP", V::Txt(r#""swap""#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("MNTOPT_DEFAULTS", V::Txt(r#""defaults""#)),
                ("MNTOPT_RO", V::Txt(r#""ro""#)),
                ("MNTOPT_RW", V::Txt(r#""rw""#)),
                ("MNTOPT_SUID", V::Txt(r#""suid""#)),
                ("MNTOPT_NOSUID", V::Txt(r#""nosuid""#)),
                ("MNTOPT_NOAUTO", V::Txt(r#""noauto""#)),
            ]),
            Item::Blank,
            Item::Block { head: "struct mntent ", body: &["", "  char *mnt_fsname;", "  char *mnt_dir;", "  char *mnt_type;", "  char *mnt_opts;", "  int mnt_freq;", "  int mnt_passno;", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-mntentcalls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_MISC", items: &[
                    Item::Include("<bits/rlibc-mntentcalls-misc.h>"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
