use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/waitstatus.h",
    items: &[
        Item::Guard { name: "_BITS_WAITSTATUS_H", value: "1", end: "", items: &[
            Item::Raw(Reason::StdMacro, "#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)"),
            Item::Raw(Reason::StdMacro, "#define WTERMSIG(status) ((status) & 0x7f)"),
            Item::Raw(Reason::StdMacro, "#define WSTOPSIG(status) WEXITSTATUS(status)"),
            Item::Raw(Reason::StdMacro, "#define WIFEXITED(status) (WTERMSIG(status) == 0)"),
            Item::Raw(Reason::StdMacro, "#define WIFSIGNALED(status) (((signed char)(((status) & 0x7f) + 1) >> 1) > 0)"),
            Item::Raw(Reason::StdMacro, "#define WIFSTOPPED(status) (((status) & 0xff) == 0x7f)"),
            Item::Raw(Reason::StdMacro, "#define WIFCONTINUED(status) ((status) == 0xffff)"),
            Item::Consts(&[
                ("WCOREFLAG", V::Dec(128)),
            ]),
            Item::Raw(Reason::StdMacro, "#define WCOREDUMP(status) ((status) & WCOREFLAG)"),
            Item::Raw(Reason::StdMacro, "#define W_EXITCODE(ret, sig) ((ret) << 8 | (sig))"),
            Item::Raw(Reason::StdMacro, "#define W_STOPCODE(sig) ((sig) << 8 | 0x7f)"),
        ]},
    ],
};
