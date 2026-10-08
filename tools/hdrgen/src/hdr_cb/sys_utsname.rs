use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("_UTSNAME_SYSNAME_LENGTH", V::Dec(65)),
        ("_UTSNAME_NODENAME_LENGTH", V::Dec(65)),
        ("_UTSNAME_RELEASE_LENGTH", V::Dec(65)),
        ("_UTSNAME_VERSION_LENGTH", V::Dec(65)),
        ("_UTSNAME_MACHINE_LENGTH", V::Dec(65)),
        ("SYS_NMLN", V::Dec(65)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

