use crate::model::*;

pub static HDR: Header = Header {
    path: "semaphore.h",
    items: &[
        Item::Guard { name: "_RLIBC_SEMAPHORE_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<bits/pthreadtypes.h>"),
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Include("<bits/types/clockid_t.h>"),
            Item::Blank,
            Item::Consts(&[
                ("SEM_VALUE_MAX", V::Dec(2147483647)),
                ("SEM_FAILED", V::Txt("((sem_t *) 0)")),
            ]),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __have_sem_t", items: &[
                    Item::Consts(&[
                        ("__have_sem_t", V::Dec(1)),
                    ]),
                    Item::Block { head: "typedef union ", body: &["", "  char __size[__SIZEOF_SEM_T];", "  long int __align;", ""], tail: " sem_t" },
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-semcalls.h>"),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
