use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Block { head: "struct qelem ", body: &["", "  struct qelem *q_forw;", "  struct qelem *q_back;", "  char q_data[1];", ""], tail: "" },
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifndef __COMPAR_FN_T", items: &[
            Item::Consts(&[
                ("__COMPAR_FN_T", V::Txt("")),
            ]),
            Item::Decl("typedef int (*__compar_fn_t)(const void *, const void *);"),
            Item::Typedef("__compar_fn_t", "comparison_fn_t"),
        ] },
    ], ""),
    Item::Blank,
    Item::Block { head: "typedef enum ", body: &[" FIND, ENTER "], tail: " ACTION" },
    Item::Blank,
    Item::Block { head: "typedef struct entry ", body: &["", "  char *key;", "  void *data;", ""], tail: " ENTRY" },
    Item::Blank,
    Item::Decl("struct _ENTRY;"),
    Item::Blank,
    Item::Block { head: "struct hsearch_data ", body: &["", "  struct _ENTRY *table;", "  unsigned int size;", "  unsigned int filled;", ""], tail: "" },
    Item::Blank,
    Item::Block { head: "typedef enum ", body: &[" preorder, postorder, endorder, leaf "], tail: " VISIT" },
    Item::Blank,
    Item::Gate(&[
        Branch { head: "ifndef __ACTION_FN_T", items: &[
            Item::Consts(&[
                ("__ACTION_FN_T", V::Txt("")),
            ]),
            Item::Decl("typedef void (*__action_fn_t)(const void *__nodep, VISIT __value, int __level);"),
        ] },
    ], ""),
    Item::Decl("typedef void (*__free_fn_t)(void *__nodep);"),
    Item::Blank,
    Item::Decl("void twalk(const void *__root, __action_fn_t __action);"),
    Item::Decl("void twalk_r(const void *__root, void (*__action)(const void *__nodep, VISIT __value, void *__closure), void *__closure);"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

