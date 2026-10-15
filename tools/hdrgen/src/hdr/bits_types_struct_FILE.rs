use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_FILE.h",
    items: &[
        Item::Guard { name: "_RLIBC_STRUCT_FILE_H", value: "1", end: "", items: &[
            Item::Include("<bits/types.h>"),
            Item::Block { head: "struct _IO_FILE ", body: &[
                "",
                "  int _flags;",
                "  char *_IO_read_ptr;",
                "  char *_IO_read_end;",
                "  char *_IO_read_base;",
                "  char *_IO_write_base;",
                "  char *_IO_write_ptr;",
                "  char *_IO_write_end;",
                "  char *_IO_buf_base;",
                "  char *_IO_buf_end;",
                "  char *_IO_save_base;",
                "  char *_IO_backup_base;",
                "  char *_IO_save_end;",
                "  char __rlibc_private2[16];",
                "  int _fileno;",
                "  char __rlibc_private4[28];",
                "  __off64_t _offset;",
                "  char __rlibc_private3[64];",
                "",
            ], tail: " __attribute__ ((__aligned__ (8)))" },
        ]},
    ],
};
