use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_sigevent.h",
    items: &[
        Item::Guard { name: "__have_sigevent_t", value: "1", end: "", items: &[
            Item::Include("<bits/types/__sigval_t.h>"),
            Item::Gate(&[
                Branch { head: "ifndef SIGEV_SIGNAL", items: &[
                    Item::Consts(&[
                        ("SIGEV_SIGNAL", V::Dec(0)),
                        ("SIGEV_NONE", V::Dec(1)),
                        ("SIGEV_THREAD", V::Dec(2)),
                        ("SIGEV_THREAD_ID", V::Dec(4)),
                    ]),
                ] },
            ], ""),
            Item::Consts(&[
                ("__SIGEV_MAX_SIZE", V::Dec(64)),
                ("__SIGEV_PAD_SIZE", V::Txt("((__SIGEV_MAX_SIZE / sizeof (int)) - 4)")),
            ]),
            Item::Decl("union pthread_attr_t;"),
            Item::Block { head: "typedef struct sigevent ", body: &["", "  __sigval_t sigev_value;", "  int sigev_signo;", "  int sigev_notify;", "  union {", "    int _pad[__SIGEV_PAD_SIZE];", "    int _tid;", "    struct {", "      void (*_function)(__sigval_t);", "      union pthread_attr_t *_attribute;", "    } _sigev_thread;", "  } _sigev_un;", ""], tail: " sigevent_t" },
            Item::Consts(&[
                ("sigev_notify_function", V::Txt("_sigev_un._sigev_thread._function")),
                ("sigev_notify_attributes", V::Txt("_sigev_un._sigev_thread._attribute")),
            ]),
        ]},
    ],
};
