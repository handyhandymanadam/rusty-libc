use crate::model::*;

pub static HDR: Header = Header {
    path: "stdbit.h",
    items: &[
        Item::Guard { name: "_RLIBC_STDBIT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stddef.h>"),
            Item::Include("<stdbool.h>"),
            Item::Include("<stdint.h>"),
            Item::Blank,
            Item::Consts(&[
                ("__STDC_VERSION_STDBIT_H__", V::Txt("202311L")),
                ("__STDC_ENDIAN_LITTLE__", V::Dec(1234)),
                ("__STDC_ENDIAN_BIG__", V::Dec(4321)),
                ("__STDC_ENDIAN_NATIVE__", V::Dec(1234)),
            ]),
            Item::Blank,
            Item::ExternBegin,
            Item::Blank,
            Item::Decl("extern unsigned int stdc_leading_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_leading_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_leading_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_trailing_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_trailing_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_trailing_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_first_leading_zero_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_zero_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_zero_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_zero_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_zero_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_first_leading_one_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_one_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_one_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_one_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_leading_one_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_first_trailing_zero_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_zero_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_zero_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_zero_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_zero_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_first_trailing_one_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_one_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_one_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_one_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_first_trailing_one_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_count_zeros_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_zeros_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_zeros_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_zeros_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_zeros_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_count_ones_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_ones_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_ones_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_ones_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_count_ones_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern bool stdc_has_single_bit_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern bool stdc_has_single_bit_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern bool stdc_has_single_bit_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern bool stdc_has_single_bit_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern bool stdc_has_single_bit_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned int stdc_bit_width_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_width_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_width_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_width_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_width_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned char stdc_bit_floor_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned short stdc_bit_floor_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_floor_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned long stdc_bit_floor_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned long long stdc_bit_floor_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::Decl("extern unsigned char stdc_bit_ceil_uc (unsigned char __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned short stdc_bit_ceil_us (unsigned short __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned int stdc_bit_ceil_ui (unsigned int __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned long stdc_bit_ceil_ul (unsigned long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Decl("extern unsigned long long stdc_bit_ceil_ull (unsigned long long __x) __attribute__ ((__nothrow__, __const__));"),
            Item::Blank,
            Item::ExternEnd,
            Item::Blank,
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_leading_zeros)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_leading_zeros(x) (__builtin_stdc_leading_zeros (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_leading_zeros(x) _Generic ((x), unsigned char: stdc_leading_zeros_uc, unsigned short: stdc_leading_zeros_us, unsigned int: stdc_leading_zeros_ui, unsigned long: stdc_leading_zeros_ul, unsigned long long: stdc_leading_zeros_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_leading_ones)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_leading_ones(x) (__builtin_stdc_leading_ones (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_leading_ones(x) _Generic ((x), unsigned char: stdc_leading_ones_uc, unsigned short: stdc_leading_ones_us, unsigned int: stdc_leading_ones_ui, unsigned long: stdc_leading_ones_ul, unsigned long long: stdc_leading_ones_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_trailing_zeros)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_trailing_zeros(x) (__builtin_stdc_trailing_zeros (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_trailing_zeros(x) _Generic ((x), unsigned char: stdc_trailing_zeros_uc, unsigned short: stdc_trailing_zeros_us, unsigned int: stdc_trailing_zeros_ui, unsigned long: stdc_trailing_zeros_ul, unsigned long long: stdc_trailing_zeros_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_trailing_ones)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_trailing_ones(x) (__builtin_stdc_trailing_ones (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_trailing_ones(x) _Generic ((x), unsigned char: stdc_trailing_ones_uc, unsigned short: stdc_trailing_ones_us, unsigned int: stdc_trailing_ones_ui, unsigned long: stdc_trailing_ones_ul, unsigned long long: stdc_trailing_ones_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_first_leading_zero)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_first_leading_zero(x) (__builtin_stdc_first_leading_zero (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_first_leading_zero(x) _Generic ((x), unsigned char: stdc_first_leading_zero_uc, unsigned short: stdc_first_leading_zero_us, unsigned int: stdc_first_leading_zero_ui, unsigned long: stdc_first_leading_zero_ul, unsigned long long: stdc_first_leading_zero_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_first_leading_one)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_first_leading_one(x) (__builtin_stdc_first_leading_one (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_first_leading_one(x) _Generic ((x), unsigned char: stdc_first_leading_one_uc, unsigned short: stdc_first_leading_one_us, unsigned int: stdc_first_leading_one_ui, unsigned long: stdc_first_leading_one_ul, unsigned long long: stdc_first_leading_one_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_first_trailing_zero)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_first_trailing_zero(x) (__builtin_stdc_first_trailing_zero (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_first_trailing_zero(x) _Generic ((x), unsigned char: stdc_first_trailing_zero_uc, unsigned short: stdc_first_trailing_zero_us, unsigned int: stdc_first_trailing_zero_ui, unsigned long: stdc_first_trailing_zero_ul, unsigned long long: stdc_first_trailing_zero_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_first_trailing_one)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_first_trailing_one(x) (__builtin_stdc_first_trailing_one (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_first_trailing_one(x) _Generic ((x), unsigned char: stdc_first_trailing_one_uc, unsigned short: stdc_first_trailing_one_us, unsigned int: stdc_first_trailing_one_ui, unsigned long: stdc_first_trailing_one_ul, unsigned long long: stdc_first_trailing_one_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_count_zeros)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_count_zeros(x) (__builtin_stdc_count_zeros (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_count_zeros(x) _Generic ((x), unsigned char: stdc_count_zeros_uc, unsigned short: stdc_count_zeros_us, unsigned int: stdc_count_zeros_ui, unsigned long: stdc_count_zeros_ul, unsigned long long: stdc_count_zeros_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_count_ones)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_count_ones(x) (__builtin_stdc_count_ones (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_count_ones(x) _Generic ((x), unsigned char: stdc_count_ones_uc, unsigned short: stdc_count_ones_us, unsigned int: stdc_count_ones_ui, unsigned long: stdc_count_ones_ul, unsigned long long: stdc_count_ones_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_has_single_bit)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_has_single_bit(x) (__builtin_stdc_has_single_bit (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_has_single_bit(x) _Generic ((x), unsigned char: stdc_has_single_bit_uc, unsigned short: stdc_has_single_bit_us, unsigned int: stdc_has_single_bit_ui, unsigned long: stdc_has_single_bit_ul, unsigned long long: stdc_has_single_bit_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_bit_width)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_bit_width(x) (__builtin_stdc_bit_width (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_bit_width(x) _Generic ((x), unsigned char: stdc_bit_width_uc, unsigned short: stdc_bit_width_us, unsigned int: stdc_bit_width_ui, unsigned long: stdc_bit_width_ul, unsigned long long: stdc_bit_width_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_bit_floor)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_bit_floor(x) (__builtin_stdc_bit_floor (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_bit_floor(x) _Generic ((x), unsigned char: stdc_bit_floor_uc, unsigned short: stdc_bit_floor_us, unsigned int: stdc_bit_floor_ui, unsigned long: stdc_bit_floor_ul, unsigned long long: stdc_bit_floor_ull) (x)"),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "if defined __has_builtin && __has_builtin (__builtin_stdc_bit_ceil)", items: &[
                    Item::Raw(Reason::StdMacro, "# define stdc_bit_ceil(x) (__builtin_stdc_bit_ceil (x))"),
                ] },
                Branch { head: "else", items: &[
                    Item::Raw(Reason::Generic, "#define stdc_bit_ceil(x) _Generic ((x), unsigned char: stdc_bit_ceil_uc, unsigned short: stdc_bit_ceil_us, unsigned int: stdc_bit_ceil_ui, unsigned long: stdc_bit_ceil_ul, unsigned long long: stdc_bit_ceil_ull) (x)"),
                ] },
            ], ""),
            Item::Blank,
        ]},
    ],
};
