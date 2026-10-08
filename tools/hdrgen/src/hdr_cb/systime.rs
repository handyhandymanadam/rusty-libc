use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/time_t.h>"),
    Item::Include("<bits/types/struct_timeval.h>"),
    Item::Include("<bits/types/suseconds_t.h>"),
    Item::Blank,
    Item::Raw(Reason::GlibcMacro, "#define TIMEVAL_TO_TIMESPEC(tv, ts) { (ts)->tv_sec = (tv)->tv_sec; (ts)->tv_nsec = (tv)->tv_usec * 1000; }"),
    Item::Raw(Reason::GlibcMacro, "#define TIMESPEC_TO_TIMEVAL(tv, ts) { (tv)->tv_sec = (ts)->tv_sec; (tv)->tv_usec = (ts)->tv_nsec / 1000; }"),
    Item::Blank,
    Item::Block { head: "struct timezone ", body: &["", "  int tz_minuteswest;", "  int tz_dsttime;", ""], tail: "" },
    Item::Blank,
    Item::Block { head: "struct itimerval ", body: &["", "  struct timeval it_interval;", "  struct timeval it_value;", ""], tail: "" },
    Item::Blank,
    Item::Block { head: "enum __itimer_which ", body: &["", "  ITIMER_REAL = 0,", "#define ITIMER_REAL ITIMER_REAL", "  ITIMER_VIRTUAL = 1,", "#define ITIMER_VIRTUAL ITIMER_VIRTUAL", "  ITIMER_PROF = 2", "#define ITIMER_PROF ITIMER_PROF", ""], tail: "" },
    Item::Blank,
    Item::Raw(Reason::GlibcMacro, "#define timerisset(tvp) ((tvp)->tv_sec || (tvp)->tv_usec)"),
    Item::Raw(Reason::GlibcMacro, "#define timerclear(tvp) ((tvp)->tv_sec = (tvp)->tv_usec = 0)"),
    Item::Raw(Reason::GlibcMacro, "#define timercmp(a, b, CMP) (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec CMP (b)->tv_usec) : ((a)->tv_sec CMP (b)->tv_sec))"),
    Item::Raw(Reason::GlibcMacro, "#define timeradd(a, b, result) do { (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; if ((result)->tv_usec >= 1000000) { ++(result)->tv_sec; (result)->tv_usec -= 1000000; } } while (0)"),
    Item::Raw(Reason::GlibcMacro, "#define timersub(a, b, result) do { (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; if ((result)->tv_usec < 0) { --(result)->tv_sec; (result)->tv_usec += 1000000; } } while (0)"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

