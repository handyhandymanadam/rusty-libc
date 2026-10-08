use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("ST_RDONLY", V::Dec(1)),
        ("ST_NOSUID", V::Dec(2)),
        ("ST_NODEV", V::Dec(4)),
        ("ST_NOEXEC", V::Dec(8)),
        ("ST_SYNCHRONOUS", V::Dec(16)),
        ("ST_MANDLOCK", V::Dec(64)),
        ("ST_WRITE", V::Dec(128)),
        ("ST_APPEND", V::Dec(256)),
        ("ST_IMMUTABLE", V::Dec(512)),
        ("ST_NOATIME", V::Dec(1024)),
        ("ST_NODIRATIME", V::Dec(2048)),
        ("ST_RELATIME", V::Hex(0x1000)),
        ("ST_NOSYMFOLLOW", V::Hex(0x2000)),
    ]),
    Item::Blank,
    Item::Block { head: "struct statvfs64 ", body: &["", "  unsigned long f_bsize;", "  unsigned long f_frsize;", "  uint64_t f_blocks;", "  uint64_t f_bfree;", "  uint64_t f_bavail;", "  uint64_t f_files;", "  uint64_t f_ffree;", "  uint64_t f_favail;", "  unsigned long f_fsid;", "  unsigned long f_flag;", "  unsigned long f_namemax;", "  unsigned int f_type;", "  int __f_spare[5];", ""], tail: "" },
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

