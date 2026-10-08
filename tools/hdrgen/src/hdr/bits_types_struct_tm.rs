use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/types/struct_tm.h",
    items: &[
        Item::Guard { name: "__struct_tm_defined", value: "1", end: "", items: &[
            Item::Block { head: "struct tm ", body: &["", "  int tm_sec;", "  int tm_min;", "  int tm_hour;", "  int tm_mday;", "  int tm_mon;", "  int tm_year;", "  int tm_wday;", "  int tm_yday;", "  int tm_isdst;", "  long tm_gmtoff;", "  const char *tm_zone;", ""], tail: "" },
        ]},
    ],
};
