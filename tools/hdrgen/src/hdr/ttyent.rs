use crate::model::*;

pub static HDR: Header = Header {
    path: "ttyent.h",
    items: &[
        Item::Comment("/* ttyent.h for the Rust libc (crates/rusty-libc-extra/src/ttyent.rs): the terminal table, /etc/ttys. */"),
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
            Item::Block { head: "struct ttyent ", body: &["", "  char *ty_name;                /* terminal device name */", "  char *ty_getty;               /* command to execute, usually getty */", "  char *ty_type;                /* terminal type for termcap */", "#define TTY_ON 0x01             /* enable logins (start ty_getty program) */", "#define TTY_SECURE 0x02         /* allow uid of 0 to login */", "  int ty_status;                /* status flags */", "  char *ty_window;              /* command to start up window manager */", "  char *ty_comment;             /* comment field */", ""], tail: "" },
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ttyentcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
