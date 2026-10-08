use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Consts(&[
        ("RB_AUTOBOOT", V::Txt("0x01234567")),
        ("RB_HALT_SYSTEM", V::Hex(0xcdef0123)),
        ("RB_ENABLE_CAD", V::Hex(0x89abcdef)),
        ("RB_DISABLE_CAD", V::Dec(0)),
        ("RB_POWER_OFF", V::Hex(0x4321fedc)),
        ("RB_SW_SUSPEND", V::Hex(0xd000fce2)),
        ("RB_KEXEC", V::Hex(0x45584543)),
    ]),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

