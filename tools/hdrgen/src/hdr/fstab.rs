use crate::model::*;

pub static HDR: Header = Header {
    path: "fstab.h",
    items: &[
        Item::Comment("/* fstab.h for the Rust libc (crates/rusty-libc-extra/src/fstab.rs): the file system table, /etc/fstab. */"),
        Item::Guard { name: "_RLIBC_FSTAB_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Blank,
            Item::Consts(&[
                ("_PATH_FSTAB", V::Txt(r#""/etc/fstab""#)),
                ("FSTAB", V::Txt(r#""/etc/fstab"      /* deprecated */"#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("FSTAB_RW", V::Txt(r#""rw"           /* read/write device */"#)),
                ("FSTAB_RQ", V::Txt(r#""rq"           /* read/write with quotas */"#)),
                ("FSTAB_RO", V::Txt(r#""ro"           /* read-only device */"#)),
                ("FSTAB_SW", V::Txt(r#""sw"           /* swap device */"#)),
                ("FSTAB_XX", V::Txt(r#""xx"           /* ignore totally */"#)),
            ]),
            Item::Blank,
            Item::Block { head: "struct fstab ", body: &["", "  char *fs_spec;                /* block special device name */", "  char *fs_file;                /* file system path prefix */", "  char *fs_vfstype;             /* file system type, ufs, nfs */", "  char *fs_mntops;              /* mount options ala -o */", "  const char *fs_type;          /* FSTAB_* from fs_mntops */", "  int fs_freq;                  /* dump frequency, in days */", "  int fs_passno;                /* pass number on parallel dump */", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-fstabcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
