use crate::model::*;

pub static HDR: Header = Header {
    path: "fts.h",
    items: &[
        Item::Comment(r#"/* fts.h for the Rust libc (crates/rusty-libc-extra/src/fts.rs): the file tree walk of 4.4BSD. The structures
   and constants are written here (the layouts are glibc's: FTS 72 bytes, FTSENT 120 bytes with the one
   byte name); the prototypes are generated (bits/rlibc-ftscalls.h). On x86-64 the 64-bit file offset
   structures are the plain ones, so the fts64_* functions are the same code. */"#),
        Item::Guard { name: "_RLIBC_FTS_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  struct _ftsent *fts_cur;      /* current node */", "  struct _ftsent *fts_child;    /* linked list of children */", "  struct _ftsent **fts_array;   /* sort array */", "  dev_t fts_dev;                /* starting device number */", "  char *fts_path;               /* path for this descent */", "  int fts_rfd;                  /* fd for root */", "  int fts_pathlen;              /* size of the path buffer */", "  int fts_nitems;               /* elements in the sort array */", "  int (*fts_compar) (const void *, const void *); /* compare function */", "#define FTS_COMFOLLOW 0x0001    /* follow command line symlinks */", "#define FTS_LOGICAL 0x0002      /* logical walk */", "#define FTS_NOCHDIR 0x0004      /* do not change directories */", "#define FTS_NOSTAT 0x0008       /* do not get stat info */", "#define FTS_PHYSICAL 0x0010     /* physical walk */", "#define FTS_SEEDOT 0x0020       /* return dot and dot-dot */", "#define FTS_XDEV 0x0040         /* do not cross devices */", "#define FTS_WHITEOUT 0x0080     /* return whiteout information */", "#define FTS_OPTIONMASK 0x00ff   /* valid user option mask */", "#define FTS_NAMEONLY 0x0100     /* (private) child names only */", "#define FTS_STOP 0x0200         /* (private) unrecoverable error */", "  int fts_options;              /* fts_open options, global flags */", ""], tail: " FTS" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Block { head: "typedef struct ", body: &["", "  struct _ftsent64 *fts_cur;", "  struct _ftsent64 *fts_child;", "  struct _ftsent64 **fts_array;", "  dev_t fts_dev;", "  char *fts_path;", "  int fts_rfd;", "  int fts_pathlen;", "  int fts_nitems;", "  int (*fts_compar) (const void *, const void *);", "  int fts_options;", ""], tail: " FTS64" },
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "typedef struct _ftsent ", body: &["", "  struct _ftsent *fts_cycle;    /* cycle node */", "  struct _ftsent *fts_parent;   /* parent directory */", "  struct _ftsent *fts_link;     /* next file in directory */", "  long fts_number;              /* local numeric value */", "  void *fts_pointer;            /* local address value */", "  char *fts_accpath;            /* access path */", "  char *fts_path;               /* root path */", "  int fts_errno;                /* errno for this node */", "  int fts_symfd;                /* fd for symlink */", "  unsigned short fts_pathlen;   /* strlen(fts_path) */", "  unsigned short fts_namelen;   /* strlen(fts_name) */", "  ino_t fts_ino;                /* inode */", "  dev_t fts_dev;                /* device */", "  nlink_t fts_nlink;            /* link count */", "#define FTS_ROOTPARENTLEVEL -1", "#define FTS_ROOTLEVEL 0", "  short fts_level;              /* depth (-1 to N) */", "#define FTS_D 1                 /* preorder directory */", "#define FTS_DC 2                /* directory that causes cycles */", "#define FTS_DEFAULT 3           /* none of the above */", "#define FTS_DNR 4               /* unreadable directory */", "#define FTS_DOT 5               /* dot or dot-dot */", "#define FTS_DP 6                /* postorder directory */", "#define FTS_ERR 7               /* error; errno is set */", "#define FTS_F 8                 /* regular file */", "#define FTS_INIT 9              /* initialized only */", "#define FTS_NS 10               /* stat(2) failed */", "#define FTS_NSOK 11             /* no stat(2) requested */", "#define FTS_SL 12               /* symbolic link */", "#define FTS_SLNONE 13           /* symbolic link without target */", "#define FTS_W 14                /* whiteout object */", "  unsigned short fts_info;      /* flags for the FTSENT structure */", "#define FTS_DONTCHDIR 0x01      /* do not chdir .. to the parent */", "#define FTS_SYMFOLLOW 0x02      /* followed a symlink to get here */", "  unsigned short fts_flags;     /* private flags for the FTSENT structure */", "#define FTS_AGAIN 1             /* read node again */", "#define FTS_FOLLOW 2            /* follow symbolic link */", "#define FTS_NOINSTR 3           /* no instructions */", "#define FTS_SKIP 4              /* discard node */", "  unsigned short fts_instr;     /* fts_set() instructions */", "  struct stat *fts_statp;       /* stat(2) information */", "  char fts_name[1];             /* file name */", ""], tail: " FTSENT" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Block { head: "typedef struct _ftsent64 ", body: &["", "  struct _ftsent64 *fts_cycle;", "  struct _ftsent64 *fts_parent;", "  struct _ftsent64 *fts_link;", "  long fts_number;", "  void *fts_pointer;", "  char *fts_accpath;", "  char *fts_path;", "  int fts_errno;", "  int fts_symfd;", "  unsigned short fts_pathlen;", "  unsigned short fts_namelen;", "  ino64_t fts_ino;", "  dev_t fts_dev;", "  nlink_t fts_nlink;", "  short fts_level;", "  unsigned short fts_info;", "  unsigned short fts_flags;", "  unsigned short fts_instr;", "  struct stat64 *fts_statp;", "  char fts_name[1];", ""], tail: " FTSENT64" },
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Include("<bits/rlibc-ftscalls.h>"),
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Decl("FTSENT64 *fts64_children (FTS64 *, int);"),
                    Item::Decl("int fts64_close (FTS64 *);"),
                    Item::Decl("FTS64 *fts64_open (char * const *, int, int (*) (const FTSENT64 **, const FTSENT64 **));"),
                    Item::Decl("FTSENT64 *fts64_read (FTS64 *);"),
                    Item::Decl("int fts64_set (FTS64 *, FTSENT64 *, int) __attribute__ ((__nothrow__));"),
                ] },
            ], ""),
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
