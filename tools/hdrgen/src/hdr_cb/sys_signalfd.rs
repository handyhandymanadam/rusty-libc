use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("SFD_CLOEXEC", V::Hex(0x80000)),
        ("SFD_NONBLOCK", V::Dec(2048)),
    ]),
    Item::Blank,
    Item::Block { head: "struct signalfd_siginfo ", body: &["", "  uint32_t ssi_signo;", "  int32_t ssi_errno;", "  int32_t ssi_code;", "  uint32_t ssi_pid;", "  uint32_t ssi_uid;", "  int32_t ssi_fd;", "  uint32_t ssi_tid;", "  uint32_t ssi_band;", "  uint32_t ssi_overrun;", "  uint32_t ssi_trapno;", "  int32_t ssi_status;", "  int32_t ssi_int;", "  uint64_t ssi_ptr;", "  uint64_t ssi_utime;", "  uint64_t ssi_stime;", "  uint64_t ssi_addr;", "  uint16_t ssi_addr_lsb;", "  uint16_t __pad2;", "  int32_t ssi_syscall;", "  uint64_t ssi_call_addr;", "  uint32_t ssi_arch;", "  uint8_t __pad[28];", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

