use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/gmon.h",
    items: &[
        Item::Guard { name: "_SYS_GMON_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<stdint.h>"),
            Item::Blank,
            Item::Consts(&[
                ("GMON_PROF_ON", V::Sp(r#"	0"#)),
                ("GMON_PROF_BUSY", V::Sp(r#"	1"#)),
                ("GMON_PROF_ERROR", V::Sp(r#"	2"#)),
                ("GMON_PROF_OFF", V::Sp(r#"	3"#)),
                ("GMON_PROF_REDIRECT", V::Sp(r#"	4"#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("HISTFRACTION", V::Sp(r#"	2"#)),
                ("HASHFRACTION", V::Sp(r#"	2"#)),
                ("ARCDENSITY", V::Sp(r#"	3"#)),
                ("MINARCS", V::Sp(r#"		50"#)),
                ("MAXARCS", V::Sp(r#"		((1 << 20))"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct tostruct
"#, body: &["", "  unsigned long selfpc;", "  long count;", "  unsigned short link;", "  unsigned short pad;", ""], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct rawarc
"#, body: &["", "  unsigned long raw_frompc;", "  unsigned long raw_selfpc;", "  long raw_count;", ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define ROUNDDOWN(x,y)	(((x)/(y))*(y))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define ROUNDUP(x,y)	((((x)+(y)-1)/(y))*(y))"#),
            Item::Blank,
            Item::Block { head: r#"struct gmonparam
"#, body: &["", "  long int state;", "  unsigned short *kcount;", "  size_t kcountsize;", "  unsigned long *froms;", "  size_t fromssize;", "  struct tostruct *tos;", "  size_t tossize;", "  long tolimit;", "  unsigned long lowpc;", "  unsigned long highpc;", "  unsigned long textsize;", "  unsigned long hashfraction;", "  long int log_hashfraction;", ""], tail: "" },
            Item::Decl("extern struct gmonparam _gmonparam;"),
            Item::Blank,
            Item::Decl("__BEGIN_DECLS"),
            Item::Blank,
            Item::Decl("extern void __monstartup (unsigned long __lowpc, unsigned long __highpc) __THROW;"),
            Item::Decl("extern void monstartup (unsigned long __lowpc, unsigned long __highpc) __THROW;"),
            Item::Blank,
            Item::Decl("extern void _mcleanup (void) __THROW;"),
            Item::Blank,
            Item::Decl("__END_DECLS"),
            Item::Blank,
        ]},
    ],
};
