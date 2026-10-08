use crate::model::*;

pub static HDR: Header = Header {
    path: "aio.h",
    items: &[
        Item::Guard { name: "_AIO_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<bits/types/struct_sigevent.h>"),
            Item::Include("<bits/types/struct_timespec.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_AIO_GNU", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _GNU_SOURCE || defined _LARGEFILE64_SOURCE", items: &[
                    Item::Consts(&[
                        ("__RLIBC_AIO_LFS64", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64", items: &[
                    Item::Consts(&[
                        ("__RLIBC_AIO_FOFF64", V::Dec(1)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct aiocb ", body: &["", "  int aio_fildes;", "  int aio_lio_opcode;", "  int aio_reqprio;", "  volatile void *aio_buf;", "  size_t aio_nbytes;", "  struct sigevent aio_sigevent;", "", "  struct aiocb *__next_prio;", "  int __abs_prio;", "  int __policy;", "  int __error_code;", "  ssize_t __return_value;", "", "  off_t aio_offset;", "  char __glibc_reserved[32];", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_AIO_LFS64", items: &[
                    Item::Block { head: "struct aiocb64 ", body: &["", "  int aio_fildes;", "  int aio_lio_opcode;", "  int aio_reqprio;", "  volatile void *aio_buf;", "  size_t aio_nbytes;", "  struct sigevent aio_sigevent;", "", "  struct aiocb *__next_prio;", "  int __abs_prio;", "  int __policy;", "  int __error_code;", "  ssize_t __return_value;", "", "  off64_t aio_offset;", "  char __glibc_reserved[32];", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_AIO_GNU", items: &[
                    Item::Block { head: "struct aioinit ", body: &["", "  int aio_threads;", "  int aio_num;", "  int aio_locks;", "  int aio_usedba;", "  int aio_debug;", "  int aio_numusers;", "  int aio_idle_time;", "  int aio_reserved;", ""], tail: "" },
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  AIO_CANCELED,", "#define AIO_CANCELED AIO_CANCELED", "  AIO_NOTCANCELED,", "#define AIO_NOTCANCELED AIO_NOTCANCELED", "  AIO_ALLDONE", "#define AIO_ALLDONE AIO_ALLDONE", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  LIO_READ,", "#define LIO_READ LIO_READ", "  LIO_WRITE,", "#define LIO_WRITE LIO_WRITE", "  LIO_NOP", "#define LIO_NOP LIO_NOP", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum ", body: &["", "  LIO_WAIT,", "#define LIO_WAIT LIO_WAIT", "  LIO_NOWAIT", "#define LIO_NOWAIT LIO_NOWAIT", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_AIO_FOFF64", items: &[
                    Item::Decl(r#"extern int aio_read (struct aiocb *__aiocbp) __asm__ ("aio_read64");"#),
                    Item::Decl(r#"extern int aio_write (struct aiocb *__aiocbp) __asm__ ("aio_write64");"#),
                    Item::Decl(r#"extern int lio_listio (int __mode, struct aiocb *const __list[], int __nent, struct sigevent *__sig) __asm__ ("lio_listio64");"#),
                    Item::Decl(r#"extern int aio_error (const struct aiocb *__aiocbp) __asm__ ("aio_error64");"#),
                    Item::Decl(r#"extern ssize_t aio_return (struct aiocb *__aiocbp) __asm__ ("aio_return64");"#),
                    Item::Decl(r#"extern int aio_cancel (int __fildes, struct aiocb *__aiocbp) __asm__ ("aio_cancel64");"#),
                    Item::Decl(r#"extern int aio_suspend (const struct aiocb *const __list[], int __nent, const struct timespec *__timeout) __asm__ ("aio_suspend64");"#),
                    Item::Decl(r#"extern int aio_fsync (int __operation, struct aiocb *__aiocbp) __asm__ ("aio_fsync64");"#),
                ] },
                Branch { head: "else", items: &[
                    Item::Include("<bits/rlibc-aio-calls.h>"),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_AIO_LFS64", items: &[
                    Item::Include("<bits/rlibc-aio-64.h>"),
                ] },
            ], ""),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_AIO_GNU", items: &[
                    Item::Include("<bits/rlibc-aio-gnu.h>"),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
