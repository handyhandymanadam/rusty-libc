use crate::model::*;

pub static HDR: Header = Header {
    path: "fmtmsg.h",
    items: &[
        Item::Guard { name: "__FMTMSG_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Block { head: r#"enum
"#, body: &["", "  MM_HARD = 0x001,", "#define MM_HARD MM_HARD", "  MM_SOFT = 0x002,", "#define MM_SOFT MM_SOFT", "  MM_FIRM = 0x004,", "#define MM_FIRM MM_FIRM", "  MM_APPL = 0x008,", "#define MM_APPL MM_APPL", "  MM_UTIL = 0x010,", "#define MM_UTIL MM_UTIL", "  MM_OPSYS = 0x020,", "#define MM_OPSYS MM_OPSYS", "  MM_RECOVER = 0x040,", "#define MM_RECOVER MM_RECOVER", "  MM_NRECOV = 0x080,", "#define MM_NRECOV MM_NRECOV", "  MM_PRINT = 0x100,", "#define MM_PRINT MM_PRINT", "  MM_CONSOLE = 0x200", "#define MM_CONSOLE MM_CONSOLE", ""], tail: "" },
            Item::Blank,
            Item::Block { head: r#"enum
"#, body: &["", "  MM_NOSEV = 0,", "#define MM_NOSEV MM_NOSEV", "  MM_HALT,", "#define MM_HALT MM_HALT", "  MM_ERROR,", "#define MM_ERROR MM_ERROR", "  MM_WARNING,", "#define MM_WARNING MM_WARNING", "  MM_INFO", "#define MM_INFO MM_INFO", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("MM_NULLLBL", V::Sp(r#"	((char *) 0)"#)),
                ("MM_NULLSEV", V::Sp(r#"	0"#)),
                ("MM_NULLMC", V::Sp(r#"	((long int) 0)"#)),
                ("MM_NULLTXT", V::Sp(r#"	((char *) 0)"#)),
                ("MM_NULLACT", V::Sp(r#"	((char *) 0)"#)),
                ("MM_NULLTAG", V::Sp(r#"	((char *) 0)"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"enum
"#, body: &["", "  MM_NOTOK = -1,", "#define MM_NOTOK MM_NOTOK", "  MM_OK = 0,", "#define MM_OK MM_OK", "  MM_NOMSG = 1,", "#define MM_NOMSG MM_NOMSG", "  MM_NOCON = 4", "#define MM_NOCON MM_NOCON", ""], tail: "" },
            Item::Blank,
            Item::Decl(r#"extern int fmtmsg (long int __classification, const char *__label,
		   int __severity, const char *__text,
		   const char *__action, const char *__tag);"#),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __USE_MISC", items: &[
                    Item::Decl("extern int addseverity (int __severity, const char *__string) __THROW;"),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};
