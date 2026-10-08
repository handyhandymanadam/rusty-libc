use crate::model::*;

pub static HDR: Header = Header {
    path: "assert.h",
    items: &[
        Item::Include("<features.h>"),
        Item::Undef("assert"),
        Item::Undef("assert_perror"),
        Item::Blank,
        Item::Undef("__ASSERT_VARIADIC"),
        Item::Gate(&[
            Branch { head: "if !defined __cplusplus && (defined __GNUC__ || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L))", items: &[
                Item::Consts(&[
                    ("__ASSERT_VARIADIC", V::Dec(1)),
                ]),
            ] },
            Branch { head: "else", items: &[
                Item::Consts(&[
                    ("__ASSERT_VARIADIC", V::Dec(0)),
                ]),
            ] },
        ], ""),
        Item::Blank,
        Item::Gate(&[
            Branch { head: "ifdef NDEBUG", items: &[
                Item::Consts(&[
                    ("__ASSERT_VOID_CAST", V::Txt("(void)")),
                ]),
                Item::Gate(&[
                    Branch { head: "if __ASSERT_VARIADIC", items: &[
                        Item::Raw(Reason::StdMacro, "#  define assert(...) (__ASSERT_VOID_CAST (0))"),
                    ] },
                    Branch { head: "else", items: &[
                        Item::Raw(Reason::StdMacro, "#  define assert(expr) (__ASSERT_VOID_CAST (0))"),
                    ] },
                ], ""),
                Item::Raw(Reason::StdMacro, "# define assert_perror(errnum) (__ASSERT_VOID_CAST (0))"),
            ] },
            Branch { head: "else", items: &[
                Item::Gate(&[
                    Branch { head: "ifndef _ASSERT_H_DECLS", items: &[
                        Item::Consts(&[
                            ("_ASSERT_H_DECLS", V::Txt("")),
                        ]),
                        Item::Gate(&[
                            Branch { head: "ifdef __cplusplus", items: &[
                                Item::Raw(Reason::Other, r#"extern "C" {"#),
                            ] },
                        ], ""),
                        Item::Decl("extern void __assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) __attribute__((__noreturn__));"),
                        Item::Decl("extern void __assert_perror_fail(int __errnum, const char *__file, unsigned int __line, const char *__function) __attribute__((__noreturn__));"),
                        Item::Decl("extern void __assert(const char *__assertion, const char *__file, int __line) __attribute__((__noreturn__));"),
                        Item::Gate(&[
                            Branch { head: "ifdef __cplusplus", items: &[
                                Item::Raw(Reason::Other, "}"),
                            ] },
                        ], ""),
                    ] },
                ], ""),
                Item::Undef("__ASSERT_VOID_CAST"),
                Item::Gate(&[
                    Branch { head: "if defined __cplusplus", items: &[
                        Item::Consts(&[
                            ("__ASSERT_VOID_CAST", V::Txt("static_cast<void>")),
                        ]),
                    ] },
                    Branch { head: "else", items: &[
                        Item::Consts(&[
                            ("__ASSERT_VOID_CAST", V::Txt("(void)")),
                        ]),
                    ] },
                ], ""),
                Item::Undef("__ASSERT_FUNCTION"),
                Item::Gate(&[
                    Branch { head: "if defined __GNUC__", items: &[
                        Item::Consts(&[
                            ("__ASSERT_FUNCTION", V::Txt("__extension__ __PRETTY_FUNCTION__")),
                        ]),
                    ] },
                    Branch { head: "elif defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L", items: &[
                        Item::Consts(&[
                            ("__ASSERT_FUNCTION", V::Txt("__func__")),
                        ]),
                    ] },
                    Branch { head: "else", items: &[
                        Item::Consts(&[
                            ("__ASSERT_FUNCTION", V::Txt("((const char *) 0)")),
                        ]),
                    ] },
                ], ""),
                Item::Gate(&[
                    Branch { head: "if __ASSERT_VARIADIC", items: &[
                        Item::Raw(Reason::StdMacro, r#"#  define assert(...) \
    ((__VA_ARGS__) ? __ASSERT_VOID_CAST (0) : __assert_fail (#__VA_ARGS__, __FILE__, __LINE__, __ASSERT_FUNCTION))"#),
                    ] },
                    Branch { head: "else", items: &[
                        Item::Raw(Reason::StdMacro, r#"#  define assert(expr) \
    ((expr) ? __ASSERT_VOID_CAST (0) : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))"#),
                    ] },
                ], ""),
                Item::Raw(Reason::StdMacro, r#"# define assert_perror(errnum) \
    (!(errnum) ? __ASSERT_VOID_CAST (0) : __assert_perror_fail ((errnum), __FILE__, __LINE__, __ASSERT_FUNCTION))"#),
            ] },
        ], ""),
        Item::Blank,
        Item::Gate(&[
            Branch { head: "ifndef _ASSERT_H", items: &[
                Item::Consts(&[
                    ("_ASSERT_H", V::Dec(1)),
                ]),
                Item::Gate(&[
                    Branch { head: "if defined __STDC_VERSION__ && __STDC_VERSION__ >= 201112L && !defined __cplusplus && !defined __STDC_VERSION_ASSERT_H__", items: &[
                        Item::Undef("static_assert"),
                        Item::Consts(&[
                            ("static_assert", V::Txt("_Static_assert")),
                        ]),
                    ] },
                ], ""),
            ] },
        ], ""),
    ],
};
