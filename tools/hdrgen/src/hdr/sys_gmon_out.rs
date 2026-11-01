use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/gmon_out.h",
    items: &[
        Item::Comment("/* sys/gmon_out.h for the Rust libc: the layout of the gmon.out file that gprof reads. */"),
        Item::Guard { name: "_SYS_GMON_OUT_H", value: "1", end: " /* sys/gmon_out.h */", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Blank,
            Item::Comment("/* Magic cookie of the file and its version. */"),
            Item::Consts(&[
                ("GMON_MAGIC", V::Sp(r#"	"gmon""#)),
                ("GMON_VERSION", V::Sp(r#"	1"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct gmon_hdr
"#, body: &["", "  char cookie[4];", "  char version[4];", "  char spare[3 * 4];", ""], tail: "" },
            Item::Blank,
            Item::Comment("/* Types of records in the file. */"),
            Item::Consts(&[
                ("GMON_TAG_TIME_HIST", V::Sp(r#"	0"#)),
                ("GMON_TAG_CG_ARC", V::Sp(r#"		1"#)),
                ("GMON_TAG_BB_COUNT", V::Sp(r#"	2"#)),
            ]),
            Item::Blank,
            Item::Comment("/* Histogram header: the text range, the number of counters, the clock rate and its unit. */"),
            Item::Block { head: r#"struct gmon_hist_hdr
"#, body: &["", "  char low_pc[sizeof (char *)];", "  char high_pc[sizeof (char *)];", "  char hist_size[4];", "  char prof_rate[4];", "  char dimen[15];", "  char dimen_abbrev;", ""], tail: "" },
            Item::Blank,
            Item::Comment("/* A call arc: the call site, the callee and how often it was taken. */"),
            Item::Block { head: r#"struct gmon_cg_arc_record
"#, body: &["", "  char from_pc[sizeof (char *)];", "  char self_pc[sizeof (char *)];", "  char count[4];", ""], tail: "" },
            Item::Blank,
        ]},
    ],
};
