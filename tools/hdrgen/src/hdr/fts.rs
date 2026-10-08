use crate::model::*;

pub static HDR: Header = Header {
    path: "fts.h",
    items: &[
        Item::Guard { name: "_RLIBC_FTS_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<bits/rlibc-features.h>"),
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Block { head: "typedef struct ", body: &["", "  struct _ftsent *fts_cur;", "  struct _ftsent *fts_child;", "  struct _ftsent **fts_array;", "  dev_t fts_dev;", "  char *fts_path;", "  int fts_rfd;", "  int fts_pathlen;", "  int fts_nitems;", "  int (*fts_compar) (const void *, const void *);", "#define FTS_COMFOLLOW 0x0001", "#define FTS_LOGICAL 0x0002", "#define FTS_NOCHDIR 0x0004", "#define FTS_NOSTAT 0x0008", "#define FTS_PHYSICAL 0x0010", "#define FTS_SEEDOT 0x0020", "#define FTS_XDEV 0x0040", "#define FTS_WHITEOUT 0x0080", "#define FTS_OPTIONMASK 0x00ff", "#define FTS_NAMEONLY 0x0100", "#define FTS_STOP 0x0200", "  int fts_options;", ""], tail: " FTS" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __RLIBC_USE_LF64", items: &[
                    Item::Block { head: "typedef struct ", body: &["", "  struct _ftsent64 *fts_cur;", "  struct _ftsent64 *fts_child;", "  struct _ftsent64 **fts_array;", "  dev_t fts_dev;", "  char *fts_path;", "  int fts_rfd;", "  int fts_pathlen;", "  int fts_nitems;", "  int (*fts_compar) (const void *, const void *);", "  int fts_options;", ""], tail: " FTS64" },
                ] },
            ], ""),
            Item::Blank,
            Item::Block { head: "typedef struct _ftsent ", body: &["", "  struct _ftsent *fts_cycle;", "  struct _ftsent *fts_parent;", "  struct _ftsent *fts_link;", "  long fts_number;", "  void *fts_pointer;", "  char *fts_accpath;", "  char *fts_path;", "  int fts_errno;", "  int fts_symfd;", "  unsigned short fts_pathlen;", "  unsigned short fts_namelen;", "  ino_t fts_ino;", "  dev_t fts_dev;", "  nlink_t fts_nlink;", "#define FTS_ROOTPARENTLEVEL -1", "#define FTS_ROOTLEVEL 0", "  short fts_level;", "#define FTS_D 1", "#define FTS_DC 2", "#define FTS_DEFAULT 3", "#define FTS_DNR 4", "#define FTS_DOT 5", "#define FTS_DP 6", "#define FTS_ERR 7", "#define FTS_F 8", "#define FTS_INIT 9", "#define FTS_NS 10", "#define FTS_NSOK 11", "#define FTS_SL 12", "#define FTS_SLNONE 13", "#define FTS_W 14", "  unsigned short fts_info;", "#define FTS_DONTCHDIR 0x01", "#define FTS_SYMFOLLOW 0x02", "  unsigned short fts_flags;", "#define FTS_AGAIN 1", "#define FTS_FOLLOW 2", "#define FTS_NOINSTR 3", "#define FTS_SKIP 4", "  unsigned short fts_instr;", "  struct stat *fts_statp;", "  char fts_name[1];", ""], tail: " FTSENT" },
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
