use crate::model::*;

pub static HDR: Header = Header {
    path: "obstack.h",
    items: &[
        Item::Guard { name: "_OBSTACK_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef __PTRDIFF_TYPE__", items: &[
                    Item::Consts(&[
                        ("PTR_INT_TYPE", V::Txt("__PTRDIFF_TYPE__")),
                    ]),
                ] },
                Branch { head: "else", items: &[
                    Item::Include("<stddef.h>"),
                    Item::Consts(&[
                        ("PTR_INT_TYPE", V::Txt("ptrdiff_t")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define __BPTR_ALIGN(B, P, A) ((B) + (((P) - (B) + (A)) & ~(A)))"),
            Item::Raw(Reason::GlibcMacro, "#define __PTR_ALIGN(B, P, A) __BPTR_ALIGN (sizeof (PTR_INT_TYPE) < sizeof (void *) ? (B) : (char *) 0, P, A)"),
            Item::Blank,
            Item::Include("<string.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __attribute_pure__", items: &[
                    Item::Gate(&[
                        Branch { head: "ifdef __GNUC__", items: &[
                            Item::Consts(&[
                                ("__attribute_pure__", V::Txt("__attribute__ ((__pure__))")),
                            ]),
                        ] },
                        Branch { head: "else", items: &[
                            Item::Consts(&[
                                ("__attribute_pure__", V::Txt("")),
                            ]),
                        ] },
                    ], ""),
                ] },
            ], ""),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Block { head: "struct _obstack_chunk ", body: &["", "  char *limit;", "  struct _obstack_chunk *prev;", "  char contents[4];", ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct obstack ", body: &["", "  long chunk_size;", "  struct _obstack_chunk *chunk;", "  char *object_base;", "  char *next_free;", "  char *chunk_limit;", "  union {", "    PTR_INT_TYPE tempint;", "    void *tempptr;", "  } temp;", "  int alignment_mask;", "  struct _obstack_chunk *(*chunkfun) (void *, long);", "  void (*freefun) (void *, struct _obstack_chunk *);", "  void *extra_arg;", "  unsigned use_extra_arg : 1;", "  unsigned maybe_empty_object : 1;", "  unsigned alloc_failed : 1;", ""], tail: "" },
            Item::Blank,
            Item::Decl("extern void _obstack_newchunk (struct obstack *, int);"),
            Item::Decl("extern int _obstack_begin (struct obstack *, int, int, void *(*) (long), void (*) (void *));"),
            Item::Decl("extern int _obstack_begin_1 (struct obstack *, int, int, void *(*) (void *, long), void (*) (void *, void *), void *);"),
            Item::Decl("extern int _obstack_memory_used (struct obstack *) __attribute_pure__;"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __obstack_free", items: &[
                    Item::Consts(&[
                        ("__obstack_free", V::Txt("obstack_free")),
                    ]),
                ] },
            ], ""),
            Item::Decl("extern void __obstack_free (struct obstack *, void *);"),
            Item::Blank,
            Item::Decl("extern void (*obstack_alloc_failed_handler) (void);"),
            Item::Decl("extern int obstack_exit_failure;"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define obstack_base(h) ((void *) (h)->object_base)"),
            Item::Raw(Reason::GlibcMacro, "#define obstack_chunk_size(h) ((h)->chunk_size)"),
            Item::Raw(Reason::GlibcMacro, "#define obstack_next_free(h) ((h)->next_free)"),
            Item::Raw(Reason::GlibcMacro, "#define obstack_alignment_mask(h) ((h)->alignment_mask)"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_init(h) \
  _obstack_begin ((h), 0, 0, (void *(*) (long)) obstack_chunk_alloc, (void (*) (void *)) obstack_chunk_free)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_begin(h, size) \
  _obstack_begin ((h), (size), 0, (void *(*) (long)) obstack_chunk_alloc, (void (*) (void *)) obstack_chunk_free)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_specify_allocation(h, size, alignment, chunkfun, freefun) \
  _obstack_begin ((h), (size), (alignment), (void *(*) (long)) (chunkfun), (void (*) (void *)) (freefun))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_specify_allocation_with_arg(h, size, alignment, chunkfun, freefun, arg) \
  _obstack_begin_1 ((h), (size), (alignment), (void *(*) (void *, long)) (chunkfun), \
                    (void (*) (void *, void *)) (freefun), (arg))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_chunkfun(h, newchunkfun) \
  ((h)->chunkfun = (struct _obstack_chunk *(*) (void *, long)) (newchunkfun))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define obstack_freefun(h, newfreefun) \
  ((h)->freefun = (void (*) (void *, struct _obstack_chunk *)) (newfreefun))"#),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define obstack_1grow_fast(h, achar) (*((h)->next_free)++ = (achar))"),
            Item::Raw(Reason::GlibcMacro, "#define obstack_blank_fast(h, n) ((h)->next_free += (n))"),
            Item::Raw(Reason::GlibcMacro, "#define obstack_memory_used(h) _obstack_memory_used (h)"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined __GNUC__", items: &[
                    Item::Gate(&[
                        Branch { head: "if ! (2 < __GNUC__ + (8 <= __GNUC_MINOR__))", items: &[
                            Item::Consts(&[
                                ("__extension__", V::Txt("")),
                            ]),
                        ] },
                    ], ""),
                    Item::Blank,
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_object_size(OBSTACK) \
  __extension__ ({ struct obstack const *__ob = (OBSTACK); (unsigned) (__ob->next_free - __ob->object_base); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_room(OBSTACK) \
  __extension__ ({ struct obstack const *__ob = (OBSTACK); (unsigned) (__ob->chunk_limit - __ob->next_free); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_make_room(OBSTACK, length) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); int __n = (length); \
                   if (__ob->chunk_limit - __ob->next_free < __n) _obstack_newchunk (__ob, __n); \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_empty_p(OBSTACK) \
  __extension__ ({ struct obstack const *__ob = (OBSTACK); \
                   (__ob->chunk->prev == 0 \
                    && __ob->next_free == __PTR_ALIGN ((char *) __ob->chunk, __ob->chunk->contents, __ob->alignment_mask)); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_grow(OBSTACK, where, length) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); int __n = (length); \
                   if (__ob->next_free + __n > __ob->chunk_limit) _obstack_newchunk (__ob, __n); \
                   memcpy (__ob->next_free, where, __n); \
                   __ob->next_free += __n; \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_grow0(OBSTACK, where, length) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); int __n = (length); \
                   if (__ob->next_free + __n + 1 > __ob->chunk_limit) _obstack_newchunk (__ob, __n + 1); \
                   memcpy (__ob->next_free, where, __n); \
                   __ob->next_free += __n; \
                   *(__ob->next_free)++ = 0; \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_1grow(OBSTACK, datum) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); \
                   if (__ob->next_free + 1 > __ob->chunk_limit) _obstack_newchunk (__ob, 1); \
                   obstack_1grow_fast (__ob, datum); \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_ptr_grow(OBSTACK, datum) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); \
                   if (__ob->next_free + sizeof (void *) > __ob->chunk_limit) _obstack_newchunk (__ob, sizeof (void *)); \
                   obstack_ptr_grow_fast (__ob, datum); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_int_grow(OBSTACK, datum) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); \
                   if (__ob->next_free + sizeof (int) > __ob->chunk_limit) _obstack_newchunk (__ob, sizeof (int)); \
                   obstack_int_grow_fast (__ob, datum); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_ptr_grow_fast(OBSTACK, aptr) \
  __extension__ ({ struct obstack *__ob2 = (OBSTACK); void *__at = __ob2->next_free; \
                   *(const void **) __at = (aptr); \
                   __ob2->next_free += sizeof (const void *); \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_int_grow_fast(OBSTACK, aint) \
  __extension__ ({ struct obstack *__ob2 = (OBSTACK); void *__at = __ob2->next_free; \
                   *(int *) __at = (aint); \
                   __ob2->next_free += sizeof (int); \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_blank(OBSTACK, length) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); int __n = (length); \
                   if (__ob->chunk_limit - __ob->next_free < __n) _obstack_newchunk (__ob, __n); \
                   obstack_blank_fast (__ob, __n); \
                   (void) 0; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_alloc(OBSTACK, length) \
  __extension__ ({ struct obstack *__oh = (OBSTACK); obstack_blank (__oh, (length)); obstack_finish (__oh); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_copy(OBSTACK, where, length) \
  __extension__ ({ struct obstack *__oh = (OBSTACK); obstack_grow (__oh, (where), (length)); obstack_finish (__oh); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_copy0(OBSTACK, where, length) \
  __extension__ ({ struct obstack *__oh = (OBSTACK); obstack_grow0 (__oh, (where), (length)); obstack_finish (__oh); })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_finish(OBSTACK) \
  __extension__ ({ struct obstack *__ob1 = (OBSTACK); void *__value = (void *) __ob1->object_base; \
                   if (__ob1->next_free == __value) __ob1->maybe_empty_object = 1; \
                   __ob1->next_free = __PTR_ALIGN (__ob1->object_base, __ob1->next_free, __ob1->alignment_mask); \
                   if (__ob1->next_free - (char *) __ob1->chunk > __ob1->chunk_limit - (char *) __ob1->chunk) \
                     __ob1->next_free = __ob1->chunk_limit; \
                   __ob1->object_base = __ob1->next_free; \
                   __value; })"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_free(OBSTACK, OBJ) \
  __extension__ ({ struct obstack *__ob = (OBSTACK); void *__obj = (OBJ); \
                   if (__obj > (void *) __ob->chunk && __obj < (void *) __ob->chunk_limit) \
                     __ob->next_free = __ob->object_base = (char *) __obj; \
                   else (__obstack_free) (__ob, __obj); })"#),
                    Item::Blank,
                ] },
                Branch { head: "else", items: &[
                    Item::Blank,
                    Item::Raw(Reason::GlibcMacro, "# define obstack_object_size(h) (unsigned) ((h)->next_free - (h)->object_base)"),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_room(h) (unsigned) ((h)->chunk_limit - (h)->next_free)"),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_empty_p(h) \
  ((h)->chunk->prev == 0 \
   && (h)->next_free == __PTR_ALIGN ((char *) (h)->chunk, (h)->chunk->contents, (h)->alignment_mask))"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_make_room(h, length) \
  ((h)->temp.tempint = (length), \
   (((h)->next_free + (h)->temp.tempint > (h)->chunk_limit) ? (_obstack_newchunk ((h), (h)->temp.tempint), 0) : 0))"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_grow(h, where, length) \
  ((h)->temp.tempint = (length), \
   (((h)->next_free + (h)->temp.tempint > (h)->chunk_limit) ? (_obstack_newchunk ((h), (h)->temp.tempint), 0) : 0), \
   memcpy ((h)->next_free, where, (h)->temp.tempint), \
   (h)->next_free += (h)->temp.tempint)"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_grow0(h, where, length) \
  ((h)->temp.tempint = (length), \
   (((h)->next_free + (h)->temp.tempint + 1 > (h)->chunk_limit) ? (_obstack_newchunk ((h), (h)->temp.tempint + 1), 0) : 0), \
   memcpy ((h)->next_free, where, (h)->temp.tempint), \
   (h)->next_free += (h)->temp.tempint, \
   *((h)->next_free)++ = 0)"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_1grow(h, datum) \
  ((((h)->next_free + 1 > (h)->chunk_limit) ? (_obstack_newchunk ((h), 1), 0) : 0), obstack_1grow_fast (h, datum))"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_ptr_grow(h, datum) \
  ((((h)->next_free + sizeof (char *) > (h)->chunk_limit) ? (_obstack_newchunk ((h), sizeof (char *)), 0) : 0), \
   obstack_ptr_grow_fast (h, datum))"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_int_grow(h, datum) \
  ((((h)->next_free + sizeof (int) > (h)->chunk_limit) ? (_obstack_newchunk ((h), sizeof (int)), 0) : 0), \
   obstack_int_grow_fast (h, datum))"#),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_ptr_grow_fast(h, aptr) (((const void **) ((h)->next_free += sizeof (void *)))[-1] = (aptr))"),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_int_grow_fast(h, aint) (((int *) ((h)->next_free += sizeof (int)))[-1] = (aint))"),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_blank(h, length) \
  ((h)->temp.tempint = (length), \
   (((h)->chunk_limit - (h)->next_free < (h)->temp.tempint) ? (_obstack_newchunk ((h), (h)->temp.tempint), 0) : 0), \
   obstack_blank_fast (h, (h)->temp.tempint))"#),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_alloc(h, length) (obstack_blank ((h), (length)), obstack_finish ((h)))"),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_copy(h, where, length) (obstack_grow ((h), (where), (length)), obstack_finish ((h)))"),
                    Item::Raw(Reason::GlibcMacro, "# define obstack_copy0(h, where, length) (obstack_grow0 ((h), (where), (length)), obstack_finish ((h)))"),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_finish(h) \
  (((h)->next_free == (h)->object_base ? (((h)->maybe_empty_object = 1), 0) : 0), \
   (h)->temp.tempptr = (h)->object_base, \
   (h)->next_free = __PTR_ALIGN ((h)->object_base, (h)->next_free, (h)->alignment_mask), \
   (((h)->next_free - (char *) (h)->chunk > (h)->chunk_limit - (char *) (h)->chunk) ? ((h)->next_free = (h)->chunk_limit) : 0), \
   (h)->object_base = (h)->next_free, \
   (h)->temp.tempptr)"#),
                    Item::Raw(Reason::GlibcMacro, r#"# define obstack_free(h, obj) \
  ((h)->temp.tempint = (char *) (obj) - (char *) (h)->chunk, \
   ((((h)->temp.tempint > 0 && (h)->temp.tempint < (h)->chunk_limit - (char *) (h)->chunk)) \
    ? (void) ((h)->next_free = (h)->object_base = (h)->temp.tempint + (char *) (h)->chunk) \
    : (__obstack_free) (h, (h)->temp.tempint + (char *) (h)->chunk)))"#),
                ] },
            ], ""),
            Item::Blank,
            Item::Include("<stdarg.h>"),
            Item::Decl(r#"extern int obstack_printf (struct obstack *__restrict __obstack, const char *__restrict __format, ...)
  __attribute__ ((__format__ (__printf__, 2, 3)));"#),
            Item::Decl(r#"extern int obstack_vprintf (struct obstack *__restrict __obstack, const char *__restrict __format, va_list __args)
  __attribute__ ((__format__ (__printf__, 2, 0)));"#),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
        ]},
    ],
};
