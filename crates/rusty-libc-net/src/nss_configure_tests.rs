use super::*;

#[test]
fn service_lines_as_glibc_parses_them() {
    // accepted by glibc 2.43 (measured with __nss_configure_lookup)
    for ok in [
        "files",
        "dns files",
        "files [NOTFOUND=return] dns",
        "",
        "  files   dns  ",
        "[x",
        "!files",
        "files]",
        "files [notfound=return]",
        "files [!SUCCESS=continue]",
        "files [NOTFOUND=return UNAVAIL=continue]",
        "files [ NOTFOUND = return ]",
        "files [SUCCESS=merge]",
        "files[NOTFOUND=return]",
        "files [NOTFOUND=return]dns",
        "[NOTFOUND=return] files",
        "files [NOTFOUND=return] [UNAVAIL=return]",
        "files [NOTFOUND=return] [x",
        "files [NOTFOUND=return]]",
        "files NOTFOUND=return]",
        "files [NOTFOUND=RETURN]",
        "files [NOTFOUND=return][UNAVAIL=return]",
        "files #comment",
        "files\nfiles",
    ] {
        assert!(validate_service_line(ok.as_bytes()), "{ok:?} should be accepted");
    }
    // EINVAL in glibc 2.43
    for bad in [
        "files [NOTFOUND",
        "files [BOGUS=return]",
        "files [NOTFOUND=bogus]",
        "files [NOTFOUND=return,UNAVAIL=continue]",
        "files []",
        "files [=]",
        "files [NOTFOUND=]",
        "files [UNKNOWN=return]",
        "files [NOTFOUND==return]",
        "files [NOTFOUND=return",
        "files [!!NOTFOUND=return]",
        "files [NOTFOUND=return SUCCESS]",
        "files [NOTFOUND=return SUCCESS=]",
        "files [NOTFOUND=return =return]",
        "files [NOTFOUND=return,]",
        "files [ ]",
        "files [",
        "dns [x",
        "files [A=return",
    ] {
        assert!(!validate_service_line(bad.as_bytes()), "{bad:?} should be rejected");
    }
}

#[test]
fn configure_lookup_results() {
    assert_eq!(configure_lookup(b"bogus", b"files"), -1);
    assert_eq!(configure_lookup(b"HOSTS", b"files"), -1);
    assert_eq!(configure_lookup(b"passwd", b"files systemd"), 0);
    rusty_libc_core::errno::set(0);
    assert_eq!(configure_lookup(b"hosts", b"files [NOTFOUND"), -1);
    assert_eq!(rusty_libc_core::errno::get(), 22);
    // the C shell agrees
    // SAFETY: C string literals.
    assert_eq!(unsafe { __nss_configure_lookup(c"HOSTS".as_ptr(), c"files".as_ptr()) }, -1);
}
