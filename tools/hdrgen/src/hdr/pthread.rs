use crate::model::*;

pub static HDR: Header = Header {
    path: "pthread.h",
    items: &[
        Item::Guard { name: "_RLIBC_PTHREAD_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sched.h>"),
            Item::Include("<time.h>"),
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Consts(&[
                ("PTHREAD_ATTR_NO_SIGMASK_NP", V::Txt("(-1)")),
            ]),
            Item::Include("<bits/types/clockid_t.h>"),
            Item::Include("<bits/types/sigset_t.h>"),
            Item::Include("<bits/pthreadtypes.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef PTHREAD_STACK_MIN", items: &[
                    Item::Consts(&[
                        ("PTHREAD_STACK_MIN", V::Dec(16384)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef PTHREAD_KEYS_MAX", items: &[
                    Item::Consts(&[
                        ("PTHREAD_KEYS_MAX", V::Dec(1024)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef PTHREAD_DESTRUCTOR_ITERATIONS", items: &[
                    Item::Consts(&[
                        ("PTHREAD_DESTRUCTOR_ITERATIONS", V::Dec(4)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_CREATE_JOINABLE,", "#define PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_JOINABLE", "  PTHREAD_CREATE_DETACHED", "#define PTHREAD_CREATE_DETACHED PTHREAD_CREATE_DETACHED", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_MUTEX_TIMED_NP,", "  PTHREAD_MUTEX_RECURSIVE_NP,", "  PTHREAD_MUTEX_ERRORCHECK_NP,", "  PTHREAD_MUTEX_ADAPTIVE_NP,", "  PTHREAD_MUTEX_NORMAL = PTHREAD_MUTEX_TIMED_NP,", "  PTHREAD_MUTEX_RECURSIVE = PTHREAD_MUTEX_RECURSIVE_NP,", "  PTHREAD_MUTEX_ERRORCHECK = PTHREAD_MUTEX_ERRORCHECK_NP,", "  PTHREAD_MUTEX_DEFAULT = PTHREAD_MUTEX_NORMAL,", "  PTHREAD_MUTEX_FAST_NP = PTHREAD_MUTEX_TIMED_NP", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_MUTEX_STALLED,", "  PTHREAD_MUTEX_STALLED_NP = PTHREAD_MUTEX_STALLED,", "  PTHREAD_MUTEX_ROBUST,", "  PTHREAD_MUTEX_ROBUST_NP = PTHREAD_MUTEX_ROBUST", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_PRIO_NONE,", "  PTHREAD_PRIO_INHERIT,", "  PTHREAD_PRIO_PROTECT", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PTHREAD_MUTEX_INITIALIZER", V::Txt(r#"\
  { { __PTHREAD_MUTEX_INITIALIZER (PTHREAD_MUTEX_TIMED_NP) } }"#)),
                ("PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP", V::Txt(r#"\
  { { __PTHREAD_MUTEX_INITIALIZER (PTHREAD_MUTEX_RECURSIVE_NP) } }"#)),
                ("PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP", V::Txt(r#"\
  { { __PTHREAD_MUTEX_INITIALIZER (PTHREAD_MUTEX_ERRORCHECK_NP) } }"#)),
                ("PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP", V::Txt(r#"\
  { { __PTHREAD_MUTEX_INITIALIZER (PTHREAD_MUTEX_ADAPTIVE_NP) } }"#)),
            ]),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_RWLOCK_PREFER_READER_NP,", "  PTHREAD_RWLOCK_PREFER_WRITER_NP,", "  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP,", "  PTHREAD_RWLOCK_DEFAULT_NP = PTHREAD_RWLOCK_PREFER_READER_NP", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PTHREAD_RWLOCK_INITIALIZER", V::Txt(r#"\
  { { __PTHREAD_RWLOCK_INITIALIZER (PTHREAD_RWLOCK_DEFAULT_NP) } }"#)),
                ("PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP", V::Txt(r#"\
  { { __PTHREAD_RWLOCK_INITIALIZER (PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) } }"#)),
            ]),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_INHERIT_SCHED,", "#define PTHREAD_INHERIT_SCHED PTHREAD_INHERIT_SCHED", "  PTHREAD_EXPLICIT_SCHED", "#define PTHREAD_EXPLICIT_SCHED PTHREAD_EXPLICIT_SCHED", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_SCOPE_SYSTEM,", "#define PTHREAD_SCOPE_SYSTEM PTHREAD_SCOPE_SYSTEM", "  PTHREAD_SCOPE_PROCESS", "#define PTHREAD_SCOPE_PROCESS PTHREAD_SCOPE_PROCESS", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_PROCESS_PRIVATE,", "#define PTHREAD_PROCESS_PRIVATE PTHREAD_PROCESS_PRIVATE", "  PTHREAD_PROCESS_SHARED", "#define PTHREAD_PROCESS_SHARED PTHREAD_PROCESS_SHARED", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PTHREAD_COND_INITIALIZER", V::Txt("{ { {0}, {0}, {0, 0}, 0, 0, {0, 0}, 0, 0 } }")),
            ]),
            Item::Blank,
            Item::Block { head: "struct _pthread_cleanup_buffer ", body: &["", "  void (*__routine) (void *);", "  void *__arg;", "  int __canceltype;", "  struct _pthread_cleanup_buffer *__prev;", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_CANCEL_ENABLE,", "#define PTHREAD_CANCEL_ENABLE PTHREAD_CANCEL_ENABLE", "  PTHREAD_CANCEL_DISABLE", "#define PTHREAD_CANCEL_DISABLE PTHREAD_CANCEL_DISABLE", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  PTHREAD_CANCEL_DEFERRED,", "#define PTHREAD_CANCEL_DEFERRED PTHREAD_CANCEL_DEFERRED", "  PTHREAD_CANCEL_ASYNCHRONOUS", "#define PTHREAD_CANCEL_ASYNCHRONOUS PTHREAD_CANCEL_ASYNCHRONOUS", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("PTHREAD_CANCELED", V::Txt("((void *) -1)")),
                ("PTHREAD_ONCE_INIT", V::Dec(0)),
                ("PTHREAD_BARRIER_SERIAL_THREAD", V::Dec(-1)),
                ("PTHREAD_ATTR_NOSIGMASK_NP", V::Txt("(-1)")),
            ]),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Include("<bits/rlibc-pthreadcalls.h>"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define pthread_cleanup_push(routine, arg) \
  do { \
    struct _pthread_cleanup_buffer __buffer; \
    _pthread_cleanup_push (&__buffer, (routine), (arg));"#),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define pthread_cleanup_pop(execute) \
    _pthread_cleanup_pop (&__buffer, (execute)); \
  } while (0)"#),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define pthread_cleanup_push_defer_np(routine, arg) \
  do { \
    struct _pthread_cleanup_buffer __buffer; \
    _pthread_cleanup_push_defer (&__buffer, (routine), (arg));"#),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define pthread_cleanup_pop_restore_np(execute) \
    _pthread_cleanup_pop_restore (&__buffer, (execute)); \
  } while (0)"#),
            Item::Blank,
        ]},
    ],
};
