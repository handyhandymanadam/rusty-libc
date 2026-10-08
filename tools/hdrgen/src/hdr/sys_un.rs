use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/un.h",
    items: &[
        Item::Guard { name: "_SYS_UN_H", value: "1", end: "", items: &[
            Item::Include("<stddef.h>"),
            Item::Include("<string.h>"),
            Item::Gate(&[
                Branch { head: "ifndef __sa_family_t_defined", items: &[
                    Item::ConstsFlat(&[
                        ("__sa_family_t_defined", V::Dec(1)),
                    ]),
                    Item::Typedef("unsigned short int", "sa_family_t"),
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "struct sockaddr_un ", body: &["", "  sa_family_t sun_family;", "  char sun_path[108];", ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define SUN_LEN(ptr) ((size_t) offsetof (struct sockaddr_un, sun_path) + strlen ((ptr)->sun_path))"),
        ]},
    ],
};
