use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Decl("typedef unsigned long int __cpu_mask;"),
    Item::Consts(&[
        ("SCHED_OTHER", V::Dec(0)),
        ("SCHED_FIFO", V::Dec(1)),
        ("SCHED_RR", V::Dec(2)),
        ("SCHED_NORMAL", V::Dec(0)),
        ("SCHED_BATCH", V::Dec(3)),
        ("SCHED_ISO", V::Dec(4)),
        ("SCHED_IDLE", V::Dec(5)),
        ("SCHED_DEADLINE", V::Dec(6)),
        ("SCHED_EXT", V::Dec(7)),
        ("SCHED_RESET_ON_FORK", V::Hex(0x40000000)),
        ("SCHED_FLAG_RESET_ON_FORK", V::Txt("0x01")),
        ("SCHED_FLAG_RECLAIM", V::Txt("0x02")),
        ("SCHED_FLAG_DL_OVERRUN", V::Txt("0x04")),
        ("SCHED_FLAG_KEEP_POLICY", V::Txt("0x08")),
        ("SCHED_FLAG_KEEP_PARAMS", V::Hex(0x10)),
        ("SCHED_FLAG_UTIL_CLAMP_MIN", V::Hex(0x20)),
        ("SCHED_FLAG_UTIL_CLAMP_MAX", V::Hex(0x40)),
        ("SCHED_FLAG_KEEP_ALL", V::Dec(24)),
        ("SCHED_FLAG_UTIL_CLAMP", V::Dec(96)),
        ("SCHED_ATTR_SIZE_VER0", V::Dec(48)),
        ("SCHED_ATTR_SIZE_VER1", V::Dec(56)),
        ("CSIGNAL", V::Txt("0x000000ff")),
        ("CLONE_VM", V::Txt("0x00000100")),
        ("CLONE_FS", V::Txt("0x00000200")),
        ("CLONE_FILES", V::Txt("0x00000400")),
        ("CLONE_SIGHAND", V::Txt("0x00000800")),
        ("CLONE_PIDFD", V::Txt("0x00001000")),
        ("CLONE_PTRACE", V::Txt("0x00002000")),
        ("CLONE_VFORK", V::Txt("0x00004000")),
        ("CLONE_PARENT", V::Txt("0x00008000")),
        ("CLONE_THREAD", V::Txt("0x00010000")),
        ("CLONE_NEWNS", V::Txt("0x00020000")),
        ("CLONE_SYSVSEM", V::Txt("0x00040000")),
        ("CLONE_SETTLS", V::Txt("0x00080000")),
        ("CLONE_PARENT_SETTID", V::Txt("0x00100000")),
        ("CLONE_CHILD_CLEARTID", V::Txt("0x00200000")),
        ("CLONE_DETACHED", V::Txt("0x00400000")),
        ("CLONE_UNTRACED", V::Txt("0x00800000")),
        ("CLONE_CHILD_SETTID", V::Txt("0x01000000")),
        ("CLONE_NEWCGROUP", V::Txt("0x02000000")),
        ("CLONE_NEWUTS", V::Txt("0x04000000")),
        ("CLONE_NEWIPC", V::Txt("0x08000000")),
        ("CLONE_NEWUSER", V::Hex(0x10000000)),
        ("CLONE_NEWPID", V::Hex(0x20000000)),
        ("CLONE_NEWNET", V::Hex(0x40000000)),
        ("CLONE_IO", V::Hex(0x80000000)),
        ("CLONE_NEWTIME", V::Txt("0x00000080")),
        ("CPU_SETSIZE", V::Dec(1024)),
    ]),
    Item::Blank,
    Item::Block { head: "typedef struct ", body: &["", "  unsigned long __bits[16];", ""], tail: " cpu_set_t" },
    Item::Consts(&[
        ("CPU_SETSIZE", V::Dec(1024)),
        ("__CPU_SETBITS", V::Dec(64)),
    ]),
    Item::Raw(Reason::GlibcMacro, r#"#define CPU_ZERO_S(setsize, cpusetp) \
  do { size_t __i; size_t __n = (setsize) / sizeof(unsigned long); unsigned long *__p = (unsigned long *)(cpusetp); \
       for (__i = 0; __i < __n; ++__i) __p[__i] = 0; } while (0)"#),
    Item::Raw(Reason::GlibcMacro, r#"#define CPU_SET_S(cpu, setsize, cpusetp) \
  (__extension__ ({ size_t __cpu = (cpu); __cpu / 8 < (setsize) \
     ? (((unsigned long *)(cpusetp))[__cpu / 64] |= 1UL << (__cpu % 64)) : 0UL; }))"#),
    Item::Raw(Reason::GlibcMacro, r#"#define CPU_CLR_S(cpu, setsize, cpusetp) \
  (__extension__ ({ size_t __cpu = (cpu); __cpu / 8 < (setsize) \
     ? (((unsigned long *)(cpusetp))[__cpu / 64] &= ~(1UL << (__cpu % 64))) : 0UL; }))"#),
    Item::Raw(Reason::GlibcMacro, r#"#define CPU_ISSET_S(cpu, setsize, cpusetp) \
  (__extension__ ({ size_t __cpu = (cpu); __cpu / 8 < (setsize) \
     ? ((((const unsigned long *)(cpusetp))[__cpu / 64] & (1UL << (__cpu % 64))) != 0) : 0; }))"#),
    Item::Raw(Reason::GlibcMacro, "#define CPU_COUNT_S(setsize, cpusetp) __sched_cpucount(setsize, (const cpu_set_t *)(cpusetp))"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_EQUAL_S(setsize, cpusetp1, cpusetp2) (__builtin_memcmp(cpusetp1, cpusetp2, setsize) == 0)"),
    Item::Raw(Reason::GlibcMacro, r#"#define __CPU_OP_S(setsize, destset, srcset1, srcset2, op) \
  (__extension__ ({ cpu_set_t *__dest = (destset); const unsigned long *__a = (const unsigned long *)(srcset1); \
     const unsigned long *__b = (const unsigned long *)(srcset2); size_t __n = (setsize) / sizeof(unsigned long), __i; \
     for (__i = 0; __i < __n; ++__i) ((unsigned long *)__dest)[__i] = __a[__i] op __b[__i]; __dest; }))"#),
    Item::Raw(Reason::GlibcMacro, "#define CPU_AND_S(setsize, destset, srcset1, srcset2) __CPU_OP_S(setsize, destset, srcset1, srcset2, &)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_OR_S(setsize, destset, srcset1, srcset2) __CPU_OP_S(setsize, destset, srcset1, srcset2, |)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_XOR_S(setsize, destset, srcset1, srcset2) __CPU_OP_S(setsize, destset, srcset1, srcset2, ^)"),
    Item::Consts(&[
        ("__NCPUBITS", V::Txt("(8 * sizeof (__cpu_mask))")),
    ]),
    Item::Raw(Reason::GlibcMacro, "#define CPU_ALLOC_SIZE(count) ((((count) + __NCPUBITS - 1) / __NCPUBITS) * sizeof (__cpu_mask))"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_ALLOC(count) __sched_cpualloc(count)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_FREE(cpuset) __sched_cpufree(cpuset)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_ZERO(cpusetp) CPU_ZERO_S(sizeof(cpu_set_t), cpusetp)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_SET(cpu, cpusetp) CPU_SET_S(cpu, sizeof(cpu_set_t), cpusetp)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_CLR(cpu, cpusetp) CPU_CLR_S(cpu, sizeof(cpu_set_t), cpusetp)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_ISSET(cpu, cpusetp) CPU_ISSET_S(cpu, sizeof(cpu_set_t), cpusetp)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_COUNT(cpusetp) CPU_COUNT_S(sizeof(cpu_set_t), cpusetp)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_EQUAL(cpusetp1, cpusetp2) CPU_EQUAL_S(sizeof(cpu_set_t), cpusetp1, cpusetp2)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_AND(destset, srcset1, srcset2) CPU_AND_S(sizeof(cpu_set_t), destset, srcset1, srcset2)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_OR(destset, srcset1, srcset2) CPU_OR_S(sizeof(cpu_set_t), destset, srcset1, srcset2)"),
    Item::Raw(Reason::GlibcMacro, "#define CPU_XOR(destset, srcset1, srcset2) CPU_XOR_S(sizeof(cpu_set_t), destset, srcset1, srcset2)"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

