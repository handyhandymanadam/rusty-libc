use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Include("<endian.h>"),
            Item::Include("<sys/select.h>"),
        ] },
    ], ""),
    Item::Gate(&[
        Branch { head: "ifdef __USE_MISC", items: &[
            Item::Gate(&[
                Branch { head: "ifndef __bsd_types_defined", items: &[
                    Item::Consts(&[
                        ("__bsd_types_defined", V::Dec(1)),
                    ]),
                    Item::Typedef("unsigned char", "u_char"),
                    Item::Typedef("unsigned short int", "u_short"),
                    Item::Typedef("unsigned int", "u_int"),
                    Item::Typedef("unsigned long int", "u_long"),
                    Item::Typedef("long int", "quad_t"),
                    Item::Typedef("unsigned long int", "u_quad_t"),
                    Item::Typedef("unsigned long int", "ulong"),
                    Item::Typedef("unsigned short int", "ushort"),
                    Item::Typedef("unsigned int", "uint"),
                    Item::Typedef("unsigned char", "u_int8_t"),
                    Item::Typedef("unsigned short int", "u_int16_t"),
                    Item::Typedef("unsigned int", "u_int32_t"),
                    Item::Typedef("unsigned long int", "u_int64_t"),
                    Item::Typedef("long int", "register_t"),
                    Item::Typedef("int", "daddr_t"),
                    Item::Gate(&[
                        Branch { head: "ifndef __fsid_t_defined", items: &[
                            Item::Consts(&[
                                ("__fsid_t_defined", V::Dec(1)),
                            ]),
                            Item::Block { head: "typedef struct ", body: &[" int __val[2]; "], tail: " fsid_t" },
                        ] },
                    ], ""),
                ] },
            ], ""),
        ] },
    ], ""),
    Item::Include("<bits/types/timer_t.h>"),
    Item::Include("<bits/pthreadtypes.h>"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

