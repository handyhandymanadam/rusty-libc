use crate::model::*;

// glibc 2.43's bits/libc-header-start.h, as an interface: the __GLIBC_USE values the ISO C extension feature-test macros
// select (__STDC_WANT_LIB_EXT2__, __STDC_WANT_IEC_60559_*__ of ISO/IEC TR 24731-2 and TS 18661-1/3/4, C23). The headers glibc
// starts with it (complex.h fenv.h limits.h math.h stdint.h stdio.h stdlib.h string.h tgmath.h wchar.h) include it right
// after <features.h> with __GLIBC_INTERNAL_STARTING_HEADER_IMPLEMENTATION defined (gen.rs add_libc_header_start). No
// include guard: the macros take the value the feature-test macros have when each of those headers is first included.
pub static HDR: Header = Header {
    path: "bits/libc-header-start.h",
    items: &[
        Item::Comment(r#"/* The ISO C feature-test macros of the C library's headers, evaluated each time one of the headers that
   start with it is first included (no include guard), as glibc 2.43's bits/libc-header-start.h. */"#),
        Item::Raw(Reason::Other, "#ifndef __GLIBC_INTERNAL_STARTING_HEADER_IMPLEMENTATION\n# error \"Never include <bits/libc-header-start.h> directly.\"\n#endif"),
        Item::Undef("__GLIBC_INTERNAL_STARTING_HEADER_IMPLEMENTATION"),
        Item::Include("<features.h>"),
        Item::Comment("/* __STDC_WANT_LIB_EXT2__ (ISO/IEC TR 24731-2:2010) */"),
        Item::Undef("__GLIBC_USE_LIB_EXT2"),
        Item::Raw(Reason::FeatureTest, "#if (defined __USE_GNU || (defined __STDC_WANT_LIB_EXT2__ && __STDC_WANT_LIB_EXT2__ > 0))\n# define __GLIBC_USE_LIB_EXT2 1\n#else\n# define __GLIBC_USE_LIB_EXT2 0\n#endif"),
        Item::Comment(r#"/* TS 18661-1: BFP_EXT the parts C23 left out, BFP_EXT_C23 the parts C23 has unconditionally, EXT the parts C23
   has under __STDC_WANT_IEC_60559_EXT__ */"#),
        Item::Undef("__GLIBC_USE_IEC_60559_BFP_EXT"),
        Item::Raw(Reason::FeatureTest, "#if defined __USE_GNU || defined __STDC_WANT_IEC_60559_BFP_EXT__\n# define __GLIBC_USE_IEC_60559_BFP_EXT 1\n#else\n# define __GLIBC_USE_IEC_60559_BFP_EXT 0\n#endif"),
        Item::Undef("__GLIBC_USE_IEC_60559_BFP_EXT_C23"),
        Item::Raw(Reason::FeatureTest, "#if __GLIBC_USE (IEC_60559_BFP_EXT) || __GLIBC_USE (ISOC23)\n# define __GLIBC_USE_IEC_60559_BFP_EXT_C23 1\n#else\n# define __GLIBC_USE_IEC_60559_BFP_EXT_C23 0\n#endif"),
        Item::Undef("__GLIBC_USE_IEC_60559_EXT"),
        Item::Raw(Reason::FeatureTest, "#if __GLIBC_USE (IEC_60559_BFP_EXT) || defined __STDC_WANT_IEC_60559_EXT__\n# define __GLIBC_USE_IEC_60559_EXT 1\n#else\n# define __GLIBC_USE_IEC_60559_EXT 0\n#endif"),
        Item::Comment("/* TS 18661-4: C23 has all of it but the reduction functions */"),
        Item::Undef("__GLIBC_USE_IEC_60559_FUNCS_EXT"),
        Item::Raw(Reason::FeatureTest, "#if defined __USE_GNU || defined __STDC_WANT_IEC_60559_FUNCS_EXT__\n# define __GLIBC_USE_IEC_60559_FUNCS_EXT 1\n#else\n# define __GLIBC_USE_IEC_60559_FUNCS_EXT 0\n#endif"),
        Item::Undef("__GLIBC_USE_IEC_60559_FUNCS_EXT_C23"),
        Item::Raw(Reason::FeatureTest, "#if __GLIBC_USE (IEC_60559_FUNCS_EXT) || __GLIBC_USE (ISOC23)\n# define __GLIBC_USE_IEC_60559_FUNCS_EXT_C23 1\n#else\n# define __GLIBC_USE_IEC_60559_FUNCS_EXT_C23 0\n#endif"),
        Item::Comment("/* TS 18661-3 */"),
        Item::Undef("__GLIBC_USE_IEC_60559_TYPES_EXT"),
        Item::Raw(Reason::FeatureTest, "#if defined __USE_GNU || defined __STDC_WANT_IEC_60559_TYPES_EXT__\n# define __GLIBC_USE_IEC_60559_TYPES_EXT 1\n#else\n# define __GLIBC_USE_IEC_60559_TYPES_EXT 0\n#endif"),
    ],
};
