use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/vlimit.h",
    items: &[
        Item::Guard { name: "_SYS_VLIMIT_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: r#"enum __vlimit_resource
"#, body: &["", "  LIM_NORAISE,", "  LIM_CPU,", "  LIM_FSIZE,", "  LIM_DATA,", "  LIM_STACK,", "  LIM_CORE,", "  LIM_MAXRSS", ""], tail: "" },
            Item::Consts(&[
                ("INFINITY", V::Hex(0x7fffffff)),
            ]),
            Item::Decl("extern int vlimit (enum __vlimit_resource __resource, int __value) __attribute__ ((__nothrow__));"),
            Item::Blank,
            Item::ExternEnd,
        ]},
    ],
};
