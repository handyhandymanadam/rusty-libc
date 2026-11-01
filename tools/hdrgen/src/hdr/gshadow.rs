use crate::model::*;

pub static HDR: Header = Header {
    path: "gshadow.h",
    items: &[
        Item::Comment(r#"/* gshadow.h for the Rust libc (crates/rusty-libc-util/src/pwd/sgrp.rs): the shadow group file, /etc/gshadow.
   The structure is written here; the prototypes are generated (bits/rlibc-gshadowcalls.h). */"#),
        Item::Guard { name: "_RLIBC_GSHADOW_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<paths.h>"),
            Item::Include("<stdio.h>"),
            Item::Include("<stddef.h>"),
            Item::Blank,
            Item::Consts(&[
                ("GSHADOW", V::Txt("_PATH_GSHADOW")),
            ]),
            Item::Blank,
            Item::Comment("/* Structure of the group shadow file. */"),
            Item::Block { head: "struct sgrp ", body: &["", "  char *sg_namp;                /* group name */", "  char *sg_passwd;              /* encrypted password */", "  char **sg_adm;                /* group administrator list */", "  char **sg_mem;                /* group member list */", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-gshadowcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
