use crate::model::*;

pub static HDR: Header = Header {
    path: "bits/hwcap.h",
    items: &[
        Item::Comment(r#"/* Bits of AT_HWCAP: x86-64 defines none (the processor's features come from CPUID, see <sys/platform/x86.h>). Kept so that
   code which includes <bits/hwcap.h> through its own copy of <sys/auxv.h> still compiles. */"#),
        Item::Guard { name: "_RLIBC_BITS_HWCAP_H", value: "1", end: "", items: &[
        ]},
    ],
};
