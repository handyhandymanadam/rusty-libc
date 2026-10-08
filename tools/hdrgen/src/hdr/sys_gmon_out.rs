use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/gmon_out.h",
    items: &[
        Item::Guard { name: "_SYS_GMON_OUT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<features.h>"),
            Item::Blank,
            Item::Consts(&[
                ("GMON_MAGIC", V::Sp(r#"	"gmon""#)),
                ("GMON_VERSION", V::Sp(r#"	1"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct gmon_hdr
"#, body: &["", "  char cookie[4];", "  char version[4];", "  char spare[3 * 4];", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("GMON_TAG_TIME_HIST", V::Sp(r#"	0"#)),
                ("GMON_TAG_CG_ARC", V::Sp(r#"		1"#)),
                ("GMON_TAG_BB_COUNT", V::Sp(r#"	2"#)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct gmon_hist_hdr
"#, body: &["", "  char low_pc[sizeof (char *)];", "  char high_pc[sizeof (char *)];", "  char hist_size[4];", "  char prof_rate[4];", "  char dimen[15];", "  char dimen_abbrev;", ""], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct gmon_cg_arc_record
"#, body: &["", "  char from_pc[sizeof (char *)];", "  char self_pc[sizeof (char *)];", "  char count[4];", ""], tail: "" },
            Item::Blank,
        ]},
    ],
};
