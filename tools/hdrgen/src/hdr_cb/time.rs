use crate::model::*;

pub static AFTER_INCLUDES: &[Item] = &[
    Item::Include("<bits/types/clock_t.h>"),
    Item::Include("<bits/types/time_t.h>"),
    Item::Include("<bits/types/struct_tm.h>"),
    Item::Include("<bits/types/struct_timespec.h>"),
    Item::Include("<bits/types/clockid_t.h>"),
    Item::Include("<bits/types/timer_t.h>"),
    Item::Include("<bits/types/struct_itimerspec.h>"),
    Item::Include("<bits/types/struct_sigevent.h>"),
    Item::Include("<bits/types/locale_t.h>"),
    Item::Blank,
    Item::Consts(&[
        ("CLOCKS_PER_SEC", V::Txt("((clock_t) 1000000)")),
        ("CLOCK_REALTIME", V::Dec(0)),
        ("CLOCK_MONOTONIC", V::Dec(1)),
        ("CLOCK_PROCESS_CPUTIME_ID", V::Dec(2)),
        ("CLOCK_THREAD_CPUTIME_ID", V::Dec(3)),
        ("CLOCK_MONOTONIC_RAW", V::Dec(4)),
        ("CLOCK_REALTIME_COARSE", V::Dec(5)),
        ("CLOCK_MONOTONIC_COARSE", V::Dec(6)),
        ("CLOCK_BOOTTIME", V::Dec(7)),
        ("CLOCK_REALTIME_ALARM", V::Dec(8)),
        ("CLOCK_BOOTTIME_ALARM", V::Dec(9)),
        ("CLOCK_TAI", V::Dec(11)),
        ("TIMER_ABSTIME", V::Dec(1)),
        ("TIME_UTC", V::Dec(1)),
        ("TIME_MONOTONIC", V::Dec(2)),
        ("TIME_ACTIVE", V::Dec(3)),
        ("TIME_THREAD_ACTIVE", V::Dec(4)),
    ]),
    Item::Blank,
    Item::Decl("extern char *tzname[2];"),
    Item::Decl("extern int daylight;"),
    Item::Decl("extern long timezone;"),
];
pub const AFTER_INCLUDES_CHOMP: bool = false;

