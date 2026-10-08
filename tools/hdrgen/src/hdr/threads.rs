use crate::model::*;

pub static HDR: Header = Header {
    path: "threads.h",
    items: &[
        Item::Guard { name: "_RLIBC_THREADS_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<time.h>"),
            Item::Include("<bits/pthreadtypes.h>"),
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if (!defined __STDC_VERSION__ || __STDC_VERSION__ <= 201710L || !defined __GNUC__ || __GNUC__ < 13) && !defined __cplusplus", items: &[
                    Item::Consts(&[
                        ("thread_local", V::Txt("_Thread_local")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Consts(&[
                ("ONCE_FLAG_INIT", V::Txt("{ 0 }")),
                ("TSS_DTOR_ITERATIONS", V::Dec(4)),
            ]),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &[" int __data; "], tail: " once_flag" },
            Item::Typedef("unsigned int", "tss_t"),
            Item::Decl("typedef void (*tss_dtor_t) (void *);"),
            Item::Typedef("unsigned long int", "thrd_t"),
            Item::Decl("typedef int (*thrd_start_t) (void *);"),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  thrd_success = 0,", "  thrd_busy = 1,", "  thrd_error = 2,", "  thrd_nomem = 3,", "  thrd_timedout = 4", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  mtx_plain = 0,", "  mtx_recursive = 1,", "  mtx_timed = 2", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "typedef union ", body: &["", "  char __size[__SIZEOF_PTHREAD_MUTEX_T];", "  long int __align;", ""], tail: " mtx_t" },
            Item::Blank,
            Item::Block { head: "typedef union ", body: &["", "  char __size[__SIZEOF_PTHREAD_COND_T];", "  long long int __align;", ""], tail: " cnd_t" },
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Include("<bits/rlibc-threadscalls.h>"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
