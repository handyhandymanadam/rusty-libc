use crate::model::*;

pub static HDR: Header = Header {
    path: "ttyent.h",
    items: &[
        Item::Guard { name: "_RLIBC_TTYENT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Blank,
            Item::Consts(&[
                ("_PATH_TTYS", V::Txt(r#""/etc/ttys""#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("_TTYS_OFF", V::Txt(r#""off""#)),
                ("_TTYS_ON", V::Txt(r#""on""#)),
                ("_TTYS_SECURE", V::Txt(r#""secure""#)),
                ("_TTYS_WINDOW", V::Txt(r#""window""#)),
            ]),
            Item::Blank,
            Item::Block { head: "struct ttyent ", body: &["", "  char *ty_name;", "  char *ty_getty;", "  char *ty_type;", "#define TTY_ON 0x01", "#define TTY_SECURE 0x02", "  int ty_status;", "  char *ty_window;", "  char *ty_comment;", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ttyentcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
