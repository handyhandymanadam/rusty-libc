//! The kernel's vDSO: moved to `rusty_libc_core::vdso` (every crate reads clocks through it); re-exported here.
pub use rusty_libc_core::vdso::*;

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    const AT_SYSINFO_EHDR: u64 = 33;

    #[test]
    fn auxv_matches_host_getauxval() {
        let host = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) };
        assert_ne!(host, 0, "this machine has a vDSO");
        assert_eq!(auxv_entry(AT_SYSINFO_EHDR), host);
        assert_eq!(auxv_entry(6), unsafe { libc::getauxval(libc::AT_PAGESZ) }); // AT_PAGESZ
        assert_eq!(auxv_entry(0x7fff_ffff), 0); // not present
    }

    #[test]
    fn finds_the_same_symbols_as_the_host_dynamic_linker() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = auxv_entry(AT_SYSINFO_EHDR) as usize;
        unsafe {
            for name in ["__vdso_clock_gettime", "__vdso_gettimeofday", "__vdso_time", "__vdso_clock_getres"] {
                let ours = lookup(base, name.as_bytes(), b"LINUX_2.6").unwrap_or_else(|| panic!("{name} not found"));
                // The host's dlvsym gives the address glibc itself resolved.
                let cname = std::ffi::CString::new(name).unwrap();
                let theirs = libc::dlvsym(libc::RTLD_DEFAULT, cname.as_ptr(), c"LINUX_2.6".as_ptr());
                // dlsym cannot see the vDSO on every glibc; when it can, the answers must agree.
                if !theirs.is_null() {
                    assert_eq!(ours, theirs as usize, "{name}");
                }
                assert!(ours > base && ours < base + 0x10000, "{name} lies inside the vDSO image");
            }
            assert!(lookup(base, b"__vdso_no_such_function", b"LINUX_2.6").is_none());
            assert!(lookup(base, b"__vdso_clock_gettime", b"LINUX_9.9").is_none());
            assert!(lookup(base + 8, b"__vdso_clock_gettime", b"LINUX_2.6").is_none()); // not an ELF header
        }
    }

    #[test]
    fn init_remembers_the_functions() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(base() != 0);
        assert!(clock_gettime().is_some());
        assert!(gettimeofday().is_some());
        assert!(time().is_some());
        assert!(clock_getres().is_some());
    }
}
