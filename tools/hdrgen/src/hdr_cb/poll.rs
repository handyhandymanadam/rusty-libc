use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("POLLIN", V::Txt("0x001")),
        ("POLLPRI", V::Txt("0x002")),
        ("POLLOUT", V::Txt("0x004")),
        ("POLLRDNORM", V::Txt("0x040")),
        ("POLLRDBAND", V::Txt("0x080")),
        ("POLLWRNORM", V::Hex(0x100)),
        ("POLLWRBAND", V::Hex(0x200)),
        ("POLLMSG", V::Hex(0x400)),
        ("POLLREMOVE", V::Hex(0x1000)),
        ("POLLRDHUP", V::Hex(0x2000)),
        ("POLLERR", V::Txt("0x008")),
        ("POLLHUP", V::Txt("0x010")),
        ("POLLNVAL", V::Txt("0x020")),
    ]),
    Item::Blank,
    Item::Typedef("unsigned long", "nfds_t"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

