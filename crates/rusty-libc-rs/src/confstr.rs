use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

pub use rusty_libc_rs_core::confstr::{CS_GNU_LIBC_VERSION, CS_GNU_LIBPTHREAD_VERSION, CS_PATH, CS_V5_WIDTH_RESTRICTED_ENVS, CS_V6_WIDTH_RESTRICTED_ENVS, CS_V7_WIDTH_RESTRICTED_ENVS};

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

pub fn confstr(name: i32) -> Option<Vec<u8>> {
    rusty_libc_rs_core::confstr::value(name, ilp32_env).map(<[u8]>::to_vec)
}

pub fn confstr_os(name: i32) -> Option<OsString> {
    confstr(name).map(OsString::from_vec)
}
