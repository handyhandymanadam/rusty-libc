use crate::model::*;

pub static HDR: Header = Header {
    path: "fpu_control.h",
    items: &[
        Item::Guard { name: "_FPU_CONTROL_H", value: "1", end: "", items: &[
            Item::Consts(&[
                ("_FPU_RESERVED", V::Txt("0xF0C0")),
                ("_FPU_DEFAULT", V::Txt("0x037F")),
                ("_FPU_IEEE", V::Txt("0x037F")),
                ("_FPU_EXTENDED", V::Hex(0x300)),
                ("_FPU_DOUBLE", V::Hex(0x200)),
                ("_FPU_SINGLE", V::Txt("0x0")),
                ("_FPU_RC_NEAREST", V::Txt("0x0")),
                ("_FPU_RC_DOWN", V::Hex(0x400)),
                ("_FPU_RC_UP", V::Hex(0x800)),
                ("_FPU_RC_ZERO", V::Txt("0xC00")),
                ("_FPU_MASK_IM", V::Txt("0x01")),
                ("_FPU_MASK_DM", V::Txt("0x02")),
                ("_FPU_MASK_ZM", V::Txt("0x04")),
                ("_FPU_MASK_OM", V::Txt("0x08")),
                ("_FPU_MASK_UM", V::Hex(0x10)),
                ("_FPU_MASK_PM", V::Hex(0x20)),
            ]),
            Item::Raw(Reason::GlibcMacro, r#"#define _FPU_GETCW(cw) __asm__ __volatile__ ("fnstcw %0" : "=m" (*&cw))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define _FPU_SETCW(cw) __asm__ __volatile__ ("fldcw %0" : : "m" (*&cw))"#),
            Item::Decl("typedef unsigned int fpu_control_t __attribute__ ((__mode__ (__HI__)));"),
            Item::Decl("extern fpu_control_t __fpu_control;"),
        ]},
    ],
};
