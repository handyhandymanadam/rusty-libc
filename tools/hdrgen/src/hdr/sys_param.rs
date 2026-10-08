use crate::model::*;

pub static HDR: Header = Header {
    path: "sys/param.h",
    items: &[
        Item::Guard { name: "_SYS_PARAM_H", value: "1", end: "", items: &[
            Item::Include("<features.h>"),
            Item::Include("<limits.h>"),
            Item::Include("<sys/types.h>"),
            Item::Consts(&[
                ("MAXSYMLINKS", V::Dec(20)),
                ("NOFILE", V::Dec(256)),
                ("NCARGS", V::Dec(131072)),
                ("NGROUPS", V::Txt("NGROUPS_MAX")),
                ("NOGROUP", V::Txt("(-1)")),
                ("MAXHOSTNAMELEN", V::Dec(64)),
                ("MAXPATHLEN", V::Txt("PATH_MAX")),
                ("CANBSIZ", V::Txt("MAX_CANON")),
                ("NBBY", V::Txt("CHAR_BIT")),
                ("HZ", V::Dec(100)),
                ("EXEC_PAGESIZE", V::Dec(4096)),
                ("DEV_BSIZE", V::Dec(512)),
                ("NODEV", V::Txt("((dev_t) -1)")),
            ]),
            Item::Raw(Reason::GlibcMacro, "#define setbit(a,i) ((a)[(i)/NBBY] |= 1<<((i)%NBBY))"),
            Item::Raw(Reason::GlibcMacro, "#define clrbit(a,i) ((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))"),
            Item::Raw(Reason::GlibcMacro, "#define isset(a,i) ((a)[(i)/NBBY] & (1<<((i)%NBBY)))"),
            Item::Raw(Reason::GlibcMacro, "#define isclr(a,i) (((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)"),
            Item::Raw(Reason::GlibcMacro, "#define howmany(x,y) (((x) + ((y) - 1)) / (y))"),
            Item::Raw(Reason::GlibcMacro, "#define roundup(x,y) (__builtin_constant_p (y) && powerof2 (y) ? (((x) + (y) - 1) & ~((y) - 1)) : ((((x) + ((y) - 1)) / (y)) * (y)))"),
            Item::Raw(Reason::GlibcMacro, "#define powerof2(x) ((((x) - 1) & (x)) == 0)"),
            Item::Raw(Reason::GlibcMacro, "#define MIN(a,b) (((a)<(b))?(a):(b))"),
            Item::Raw(Reason::GlibcMacro, "#define MAX(a,b) (((a)>(b))?(a):(b))"),
        ]},
    ],
};
