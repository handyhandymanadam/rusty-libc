use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("EPOLL_CLOEXEC", V::Hex(0x80000)),
        ("EPOLLIN", V::Txt("1U")),
        ("EPOLLPRI", V::Txt("2U")),
        ("EPOLLOUT", V::Txt("4U")),
        ("EPOLLRDNORM", V::Txt("64U")),
        ("EPOLLRDBAND", V::Txt("128U")),
        ("EPOLLWRNORM", V::Txt("256U")),
        ("EPOLLWRBAND", V::Txt("512U")),
        ("EPOLLMSG", V::Txt("1024U")),
        ("EPOLLERR", V::Txt("8U")),
        ("EPOLLHUP", V::Txt("16U")),
        ("EPOLLRDHUP", V::Txt("0x2000U")),
        ("EPOLLEXCLUSIVE", V::Txt("0x10000000U")),
        ("EPOLLWAKEUP", V::Txt("0x20000000U")),
        ("EPOLLONESHOT", V::Txt("0x40000000U")),
        ("EPOLLET", V::Txt("0x80000000U")),
        ("EPOLL_CTL_ADD", V::Dec(1)),
        ("EPOLL_CTL_DEL", V::Dec(2)),
        ("EPOLL_CTL_MOD", V::Dec(3)),
        ("EPOLL_IOC_TYPE", V::Txt("0x8A")),
        ("EPIOCSPARAMS", V::Txt("0x40088a01UL")),
        ("EPIOCGPARAMS", V::Txt("0x80088a02UL")),
    ]),
    Item::Blank,
    Item::Block { head: "typedef union epoll_data ", body: &["", "  void *ptr;", "  int fd;", "  uint32_t u32;", "  uint64_t u64;", ""], tail: " epoll_data_t" },
    Item::Block { head: "struct epoll_event ", body: &["", "  uint32_t events;", "  epoll_data_t data;", ""], tail: " __attribute__((__packed__))" },
    Item::Block { head: "struct epoll_params ", body: &["", "  uint32_t busy_poll_usecs;", "  uint16_t busy_poll_budget;", "  uint8_t prefer_busy_poll;", "  uint8_t __pad;", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

