//! confstr(3) values: glibc 2.43's table and rules on x86-64, from rusty-libc-rs-core's `confstr` module (the same code
//! rusty-libc's C `confstr` uses). This layer adds the probe for the 32-bit environments with std's means.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

pub use rusty_libc_rs_core::confstr::{CS_GNU_LIBC_VERSION, CS_GNU_LIBPTHREAD_VERSION, CS_PATH, CS_V5_WIDTH_RESTRICTED_ENVS, CS_V6_WIDTH_RESTRICTED_ENVS, CS_V7_WIDTH_RESTRICTED_ENVS};

/// Is the 32-bit environment ILP32_OFF32 (`offbig` false) or ILP32_OFFBIG available? As glibc's
/// `__sysconf_check_spec`: does getconf have a spec file `$GETCONF_DIR/POSIX_V6_ILP32_OFF32` (or `_OFFBIG`)?
/// GETCONF_DIR is ignored in a set-user-ID or set-group-ID program; default /usr/libexec/getconf.
fn ilp32_env(offbig: bool) -> bool {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    let secure = getuid() != geteuid() || getgid() != getegid();
    let dir = match std::env::var_os("GETCONF_DIR") {
        Some(d) if !secure => d,
        _ => OsString::from("/usr/libexec/getconf"),
    };
    let mut path = std::path::PathBuf::from(dir);
    path.push(if offbig { "POSIX_V6_ILP32_OFFBIG" } else { "POSIX_V6_ILP32_OFF32" });
    std::fs::metadata(path).is_ok()
}

/// confstr(3): the string value of configuration name `name` (without the trailing NUL), or `None` for a name the C
/// library does not know (where confstr fails with EINVAL). Same values as glibc 2.43 on x86-64.
pub fn confstr(name: i32) -> Option<Vec<u8>> {
    rusty_libc_rs_core::confstr::value(name, ilp32_env).map(<[u8]>::to_vec)
}

/// `confstr` as an `OsString` (what a PATH default is used as).
pub fn confstr_os(name: i32) -> Option<OsString> {
    confstr(name).map(OsString::from_vec)
}
