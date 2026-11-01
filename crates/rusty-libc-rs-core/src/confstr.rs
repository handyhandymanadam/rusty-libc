//! confstr(3): glibc 2.43's values on x86-64, one table and one set of rules for both faces (rusty-libc-sys's C
//! `confstr` and rusty-libc-rs's `confstr`). The only part that differs per face is the probe for the 32-bit programming
//! environments (it reads an environment variable and checks a file, which each face does with its own means), passed in
//! as a closure.
//!
//! The table is kept pointer-free at run time ([`crate::strtab`]): in libc.so.6 a table of `&[u8]` would be 61 relative
//! relocations the loader writes at every start.

use crate::strtab::{StrTab, packed_len_bytes};

/// `_CS_PATH`: a PATH value that finds all standard utilities.
pub const CS_PATH: i32 = 0;
/// `_CS_V6_WIDTH_RESTRICTED_ENVS`.
pub const CS_V6_WIDTH_RESTRICTED_ENVS: i32 = 1;
/// `_CS_GNU_LIBC_VERSION` (rusty-libc answers as glibc 2.43, whose interface it implements).
pub const CS_GNU_LIBC_VERSION: i32 = 2;
/// `_CS_GNU_LIBPTHREAD_VERSION`.
pub const CS_GNU_LIBPTHREAD_VERSION: i32 = 3;
/// `_CS_V5_WIDTH_RESTRICTED_ENVS`.
pub const CS_V5_WIDTH_RESTRICTED_ENVS: i32 = 4;
/// `_CS_V7_WIDTH_RESTRICTED_ENVS`.
pub const CS_V7_WIDTH_RESTRICTED_ENVS: i32 = 5;

/// The fixed values (name, value without NUL), glibc 2.43 x86-64. Compile-time data: index it only through `value`.
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

/// confstr's `_CS_*_WIDTH_RESTRICTED_ENVS`: the environments sysconf reports (glibc builds the list the same way).
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

/// The string for `confstr(name)` without the NUL, or `None` for a name glibc does not know (confstr's EINVAL).
/// `ilp32(offbig)` answers whether the 32-bit environment ILP32_OFF32 (`false`) or ILP32_OFFBIG (`true`) is available
/// (glibc's `__sysconf_check_spec`: a getconf spec file `$GETCONF_DIR/POSIX_V6_ILP32_OFF32` / `..._OFFBIG`); it is only
/// called for the names that depend on it.
#[inline]
pub fn value(name: i32, mut ilp32: impl FnMut(bool) -> bool) -> Option<&'static [u8]> {
    // the -m32 compiler and linker flags only while that environment is available (glibc: "" otherwise)
    match name {
        1100 | 1101 | 1116 | 1117 | 1132 | 1133 if !ilp32(false) => return Some(b""),
        1104 | 1105 | 1120 | 1121 | 1136 | 1137 if !ilp32(true) => return Some(b""),
        _ => {}
    }
    width_restricted_envs(name, &mut ilp32).or_else(|| NAMES.iter().position(|&n| n == name).map(|i| STRS.bytes(i)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_values() {
        assert_eq!(value(CS_PATH, |_| false), Some(&b"/usr/bin"[..]));
        assert_eq!(value(CS_GNU_LIBC_VERSION, |_| false), Some(&b"glibc 2.43"[..]));
        assert_eq!(value(1149, |_| false), Some(&b"POSIXLY_CORRECT=1"[..]));
        assert_eq!(value(999, |_| false), None);
        assert_eq!(value(-1, |_| false), None);
        for (n, s) in TABLE {
            if !matches!(n, 1100 | 1101 | 1116 | 1117 | 1132 | 1133 | 1104 | 1105 | 1120 | 1121 | 1136 | 1137) {
                assert_eq!(value(n, |_| false), Some(s), "{n}");
            }
        }
    }

    #[test]
    fn ilp32_rules() {
        assert_eq!(value(1100, |_| false), Some(&b""[..]));
        assert_eq!(value(1100, |o| !o), Some(&b"-m32"[..]));
        assert_eq!(value(1104, |o| !o), Some(&b""[..]));
        assert_eq!(value(1104, |o| o), Some(&b"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"[..]));
        assert_eq!(value(CS_V6_WIDTH_RESTRICTED_ENVS, |_| false), Some(&b"POSIX_V6_LP64_OFF64"[..]));
        assert_eq!(value(CS_V5_WIDTH_RESTRICTED_ENVS, |_| true), Some(&b"XBS5_ILP32_OFF32\nXBS5_ILP32_OFFBIG\nXBS5_LP64_OFF64"[..]));
        assert_eq!(value(CS_V7_WIDTH_RESTRICTED_ENVS, |o| o), Some(&b"POSIX_V7_ILP32_OFFBIG\nPOSIX_V7_LP64_OFF64"[..]));
        // the probe is not called for names that do not depend on it
        assert_eq!(value(CS_PATH, |_| panic!("probed")), Some(&b"/usr/bin"[..]));
    }
}
