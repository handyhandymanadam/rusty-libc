use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_FILE.h",
    items: &[
        Item::Comment(r#"/* The type of a stream. Complete, with glibc's size (216 bytes, aligned like a pointer), so that code can do arithmetic on FILE
   pointers and take sizeof (FILE). The named fields have glibc's offsets and meaning (the library keeps them live: stdio.h's
   inline getc_unlocked and putc_unlocked read and move the buffer pointers, as glibc's do); the rest is the library's own. */"#),
        Item::Guard { name: "_RLIBC_STRUCT_FILE_H", value: "1", end: "", items: &[
            Item::Include("<bits/types.h>"),
            Item::Block { head: "struct _IO_FILE ", body: &[
                "",
                "  int _flags;",
                "  char *_IO_read_ptr;     /* next byte to read */",
                "  char *_IO_read_end;     /* end of the buffered input */",
                "  char *_IO_read_base;",
                "  char *_IO_write_base;",
                "  char *_IO_write_ptr;    /* where the next byte goes */",
                "  char *_IO_write_end;    /* end of the room for output (equal to _IO_write_ptr when every byte must go through __overflow) */",
                "  char *_IO_buf_base;",
                "  char *_IO_buf_end;      /* end of the buffer */",
                "  char *_IO_save_base;",
                "  char *_IO_backup_base;",
                "  char *_IO_save_end;",
                "  char __rlibc_private2[16];",
                "  int _fileno;            /* the file descriptor, -1 for none */",
                "  char __rlibc_private4[28];",
                "  __off64_t _offset;",
                "  char __rlibc_private3[64];",
                "",
            ], tail: " __attribute__ ((__aligned__ (8)))" },
        ]},
    ],
};
