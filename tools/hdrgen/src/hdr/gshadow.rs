use crate::model::*;

pub static HDR: Header = Header {
    path: "gshadow.h",
    items: &[
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
            Item::Block { head: "struct sgrp ", body: &["", "  char *sg_namp;", "  char *sg_passwd;", "  char **sg_adm;", "  char **sg_mem;", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-gshadowcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
