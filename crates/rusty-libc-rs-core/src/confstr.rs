use crate::strtab::{StrTab, packed_len_bytes};

pub const CS_PATH: i32 = 0;
pub const CS_V6_WIDTH_RESTRICTED_ENVS: i32 = 1;
pub const CS_GNU_LIBC_VERSION: i32 = 2;
pub const CS_GNU_LIBPTHREAD_VERSION: i32 = 3;
pub const CS_V5_WIDTH_RESTRICTED_ENVS: i32 = 4;
pub const CS_V7_WIDTH_RESTRICTED_ENVS: i32 = 5;

pub const TABLE: [(i32, &[u8]); 61] = [
    (0, b"/usr/bin"),
    (2, b"glibc 2.43"),
    (3, b"NPTL 2.43"),
    (1000, b""),
    (1001, b""),
    (1002, b""),
    (1003, b""),
    (1004, b"-D_LARGEFILE64_SOURCE"),
    (1005, b""),
    (1006, b""),
    (1007, b"-D_LARGEFILE64_SOURCE"),
    (1100, b"-m32"),
    (1101, b"-m32"),
    (1102, b""),
    (1103, b""),
    (1104, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1105, b"-m32"),
    (1106, b""),
    (1107, b""),
    (1108, b"-m64"),
    (1109, b"-m64"),
    (1110, b""),
    (1111, b""),
    (1112, b""),
    (1113, b""),
    (1114, b""),
    (1115, b""),
    (1116, b"-m32"),
    (1117, b"-m32"),
    (1118, b""),
    (1119, b""),
    (1120, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1121, b"-m32"),
    (1122, b""),
    (1123, b""),
    (1124, b"-m64"),
    (1125, b"-m64"),
    (1126, b""),
    (1127, b""),
    (1128, b""),
    (1129, b""),
    (1130, b""),
    (1131, b""),
    (1132, b"-m32"),
    (1133, b"-m32"),
    (1134, b""),
    (1135, b""),
    (1136, b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"),
    (1137, b"-m32"),
    (1138, b""),
    (1139, b""),
    (1140, b"-m64"),
    (1141, b"-m64"),
    (1142, b""),
    (1143, b""),
    (1144, b""),
    (1145, b""),
    (1146, b""),
    (1147, b""),
    (1148, b"POSIXLY_CORRECT=1"),
    (1149, b"POSIXLY_CORRECT=1"),
];

static NAMES: [i32; 61] = {
    let mut out = [0; 61];
    let mut i = 0;
    while i < 61 {
        out[i] = TABLE[i].0;
        i += 1;
    }
    out
};

const fn table_strs() -> [&'static [u8]; 61] {
    let mut out: [&[u8]; 61] = [&[]; 61];
    let mut i = 0;
    while i < 61 {
        out[i] = TABLE[i].1;
        i += 1;
    }
    out
}

static STRS: StrTab<61, { packed_len_bytes(&table_strs()) }> = StrTab::from_bytes(&table_strs());

#[inline]
fn width_restricted_envs(name: i32, ilp32: &mut impl FnMut(bool) -> bool) -> Option<&'static [u8]> {
    macro_rules! envs {
        ($p:literal) => {
            match (ilp32(false), ilp32(true)) {
                (true, true) => concat!($p, "_ILP32_OFF32\n", $p, "_ILP32_OFFBIG\n", $p, "_LP64_OFF64").as_bytes(),
                (true, false) => concat!($p, "_ILP32_OFF32\n", $p, "_LP64_OFF64").as_bytes(),
                (false, true) => concat!($p, "_ILP32_OFFBIG\n", $p, "_LP64_OFF64").as_bytes(),
                (false, false) => concat!($p, "_LP64_OFF64").as_bytes(),
            }
        };
    }
    Some(match name {
        CS_V6_WIDTH_RESTRICTED_ENVS => envs!("POSIX_V6"),
        CS_V5_WIDTH_RESTRICTED_ENVS => envs!("XBS5"),
        CS_V7_WIDTH_RESTRICTED_ENVS => envs!("POSIX_V7"),
        _ => return None,
    })
}

#[inline]
pub fn value(name: i32, mut ilp32: impl FnMut(bool) -> bool) -> Option<&'static [u8]> {
    match name {
        1100 | 1101 | 1116 | 1117 | 1132 | 1133 if !ilp32(false) => return Some(b""),
        1104 | 1105 | 1120 | 1121 | 1136 | 1137 if !ilp32(true) => return Some(b""),
        _ => {}
    }
    width_restricted_envs(name, &mut ilp32).or_else(|| NAMES.iter().position(|&n| n == name).map(|i| STRS.bytes(i)))
}

