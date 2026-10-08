use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/ttychars.h",
    items: &[
        Item::Guard { name: "_SYS_TTYCHARS_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct ttychars ", body: &["", "  char tc_erase;", "  char tc_kill;", "  char tc_intrc;", "  char tc_quitc;", "  char tc_startc;", "  char tc_stopc;", "  char tc_eofc;", "  char tc_brkc;", "  char tc_suspc;", "  char tc_dsuspc;", "  char tc_rprntc;", "  char tc_flushc;", "  char tc_werasc;", "  char tc_lnextc;", ""], tail: "" },
            Item::Blank,
            Item::ExternEnd,
        ]},
    ],
};
