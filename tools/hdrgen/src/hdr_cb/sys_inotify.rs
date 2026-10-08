use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("IN_CLOEXEC", V::Hex(0x80000)),
        ("IN_NONBLOCK", V::Dec(2048)),
        ("IN_ACCESS", V::Txt("0x00000001")),
        ("IN_MODIFY", V::Txt("0x00000002")),
        ("IN_ATTRIB", V::Txt("0x00000004")),
        ("IN_CLOSE_WRITE", V::Txt("0x00000008")),
        ("IN_CLOSE_NOWRITE", V::Txt("0x00000010")),
        ("IN_CLOSE", V::Dec(24)),
        ("IN_OPEN", V::Txt("0x00000020")),
        ("IN_MOVED_FROM", V::Txt("0x00000040")),
        ("IN_MOVED_TO", V::Txt("0x00000080")),
        ("IN_MOVE", V::Dec(192)),
        ("IN_CREATE", V::Txt("0x00000100")),
        ("IN_DELETE", V::Txt("0x00000200")),
        ("IN_DELETE_SELF", V::Txt("0x00000400")),
        ("IN_MOVE_SELF", V::Txt("0x00000800")),
        ("IN_UNMOUNT", V::Txt("0x00002000")),
        ("IN_Q_OVERFLOW", V::Txt("0x00004000")),
        ("IN_IGNORED", V::Txt("0x00008000")),
        ("IN_ONLYDIR", V::Txt("0x01000000")),
        ("IN_DONT_FOLLOW", V::Txt("0x02000000")),
        ("IN_EXCL_UNLINK", V::Txt("0x04000000")),
        ("IN_MASK_CREATE", V::Hex(0x10000000)),
        ("IN_MASK_ADD", V::Hex(0x20000000)),
        ("IN_ISDIR", V::Hex(0x40000000)),
        ("IN_ONESHOT", V::Hex(0x80000000)),
        ("IN_ALL_EVENTS", V::Dec(4095)),
    ]),
    Item::Blank,
    Item::Block { head: "struct inotify_event ", body: &["", "  int wd;", "  uint32_t mask;", "  uint32_t cookie;", "  uint32_t len;", "  char name[];", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

