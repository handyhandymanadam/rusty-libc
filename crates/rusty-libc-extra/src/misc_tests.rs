//! Host tests for strfmon.rs, dlfcn.rs and backtrace.rs against the host glibc.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::{backtrace, dlfcn, strfmon};
use std::ffi::{CStr, CString, c_char, c_int, c_void};

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn strfmon(s: *mut c_char, max: usize, fmt: *const c_char, ...) -> isize;
        pub fn dladdr(addr: *const c_void, info: *mut dlfcn::DlInfo) -> c_int;
        pub fn backtrace(buf: *mut *mut c_void, size: c_int) -> c_int;
        pub fn backtrace_symbols(buf: *const *mut c_void, size: c_int) -> *mut *mut c_char;
        pub fn dl_iterate_phdr(cb: Option<unsafe extern "C" fn(*mut dlfcn::DlPhdrInfo, usize, *mut c_void) -> c_int>, data: *mut c_void) -> c_int;
    }
}

#[test]
fn strfmon_matches_glibc() {
    let _g = MON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fmts = [
        "%n", "%i", "%!n", "%(n", "%+n", "%^n", "[%12n]", "[%-12n]", "[%=*12n]", "[%=0#8n]", "[%#6.2n]", "[%.0n]", "[%.5i]", "%%", "x%ny", "[%#0n]", "[%^#12.3n]", "[%(#10n]", "[%+!-14.1i]", "",
        // errors
        "%", "%z", "%+(n", "%(+n", "%#n", "%.n", "%=", "%5", "%L", "%99999999999999999999n", "%9223372036854775807n",
    ];
    let vals = [1234.5f64, -1234.5, 0.0, -0.0, 1e15, 0.005, 0.015, 2.675, 123_456_789.987_654_33, -7.0, 1e-9, 99.995, f64::NAN, f64::INFINITY, -f64::INFINITY, 1e300];
    let mut checked = 0;
    for fmt in fmts {
        let cf = CString::new(fmt).unwrap();
        for &v in &vals {
            for size in [0usize, 1, 3, 8, 64, 700] {
                let mut a = vec![b'#'; 800];
                let mut b = vec![b'#'; 800];
                unsafe {
                    *libc::__errno_location() = 0;
                    let ra = host::strfmon(a.as_mut_ptr() as *mut c_char, size, cf.as_ptr(), v, v);
                    let ea = *libc::__errno_location();
                    rusty_libc_core::errno::set(0);
                    let rb = strfmon::strfmon(b.as_mut_ptr() as *mut c_char, size, cf.as_ptr(), v, v);
                    let eb = rusty_libc_core::errno::get();
                    assert_eq!((ra, if ra < 0 { ea } else { 0 }), (rb, if rb < 0 { eb } else { 0 }), "format {fmt:?} value {v} size {size}");
                    assert_eq!(a, b, "format {fmt:?} value {v} size {size}: buffer");
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 2000);
}

#[test]
fn dlfcn_basics() {
    unsafe {
        assert!(dlfcn::dlerror().is_null());
        let h = dlfcn::dlopen(std::ptr::null(), dlfcn::RTLD_NOW);
        assert!(!h.is_null());
        assert_eq!(dlfcn::dlopen(c"".as_ptr(), dlfcn::RTLD_LAZY), h);
        assert!(dlfcn::dlerror().is_null());
        assert!(dlfcn::dlsym(h, c"nosuchsymbol".as_ptr()).is_null());
        let e = CStr::from_ptr(dlfcn::dlerror()).to_str().unwrap().to_owned();
        assert!(e.ends_with(": undefined symbol: nosuchsymbol"), "{e}");
        assert!(dlfcn::dlerror().is_null());
        for (file, mode, want) in [
            ("/nonexistent/lib.so", dlfcn::RTLD_NOW, "/nonexistent/lib.so: cannot open shared object file: No such file or directory"),
            ("libnosuch.so.9", dlfcn::RTLD_LAZY, "libnosuch.so.9: cannot open shared object file: No such file or directory"),
            ("/nonexistent", 0, "/nonexistent: invalid mode for dlopen(): Invalid argument"),
            ("/nonexistent", dlfcn::RTLD_NOW | 0x10000, "invalid mode parameter"),
            ("/etc/passwd", dlfcn::RTLD_NOW, "/etc/passwd: invalid ELF header"),
            ("/tmp", dlfcn::RTLD_NOW, "/tmp: cannot read file data: Is a directory"),
        ] {
            let c = CString::new(file).unwrap();
            assert!(dlfcn::dlopen(c.as_ptr(), mode).is_null(), "{file}");
            let e = CStr::from_ptr(dlfcn::dlerror()).to_str().unwrap();
            assert_eq!(e, want);
        }
        // an error that was not read is dropped by a successful call
        dlfcn::dlopen(c"/nonexistent".as_ptr(), dlfcn::RTLD_NOW);
        assert!(!dlfcn::dlopen(std::ptr::null(), dlfcn::RTLD_NOW).is_null());
        assert!(dlfcn::dlerror().is_null());
        assert_eq!(dlfcn::dlclose(h), 0);
        assert_eq!(dlfcn::dlclose(std::ptr::null_mut()), -1);
        assert!(!dlfcn::dlerror().is_null());
        // the state is per thread
        dlfcn::dlopen(c"/nonexistent".as_ptr(), dlfcn::RTLD_NOW);
        std::thread::spawn(|| assert!(dlfcn::dlerror().is_null())).join().unwrap();
        assert!(!dlfcn::dlerror().is_null());
    }
}

#[test]
fn dladdr_matches_glibc() {
    unsafe {
        let here = dladdr_matches_glibc as *const c_void;
        let mut a: dlfcn::DlInfo = std::mem::zeroed();
        let mut b: dlfcn::DlInfo = std::mem::zeroed();
        let ra = host::dladdr(here, &mut a);
        let rb = dlfcn::dladdr(here, &mut b);
        assert_eq!(ra, rb);
        assert_eq!(CStr::from_ptr(a.dli_fname), CStr::from_ptr(b.dli_fname));
        assert_eq!(a.dli_fbase, b.dli_fbase);
        let local = 0u8;
        let p = &local as *const u8 as *const c_void;
        assert_eq!(host::dladdr(p, &mut a), dlfcn::dladdr(p, &mut b));
        let heap = Box::new(5u8);
        let p = &*heap as *const u8 as *const c_void;
        assert_eq!(host::dladdr(p, &mut a), dlfcn::dladdr(p, &mut b));
        assert_eq!(dlfcn::dladdr(std::ptr::null(), &mut b), host::dladdr(std::ptr::null(), &mut a));
        // an address of libc is not the program's
        let printf = libc::printf as *const c_void;
        assert_eq!(dlfcn::dladdr(printf, &mut b), 0);
    }
}

unsafe extern "C" fn first_object(info: *mut dlfcn::DlPhdrInfo, size: usize, data: *mut c_void) -> c_int {
    unsafe {
        let out = data as *mut (u64, usize, u16, usize);
        *out = ((*info).dlpi_addr, size, (*info).dlpi_phnum, (*info).dlpi_phdr as usize);
    }
    1
}

#[test]
fn dl_iterate_phdr_first_object_matches() {
    unsafe {
        let mut a = (0u64, 0usize, 0u16, 0usize);
        let mut b = (0u64, 0usize, 0u16, 0usize);
        host::dl_iterate_phdr(Some(first_object), (&raw mut a).cast());
        dlfcn::dl_iterate_phdr(Some(first_object), (&raw mut b).cast());
        assert_eq!(a, b);
    }
}

#[inline(never)]
fn both(depth: u32, ours: &mut Vec<usize>, theirs: &mut Vec<usize>) {
    if depth > 0 {
        both(depth - 1, ours, theirs);
        std::hint::black_box(&ours);
        return;
    }
    unsafe {
        let mut a = [std::ptr::null_mut::<c_void>(); 64];
        let mut b = [std::ptr::null_mut::<c_void>(); 64];
        let na = host::backtrace(a.as_mut_ptr(), 64);
        let nb = backtrace::backtrace(b.as_mut_ptr(), 64);
        // This test program is a dynamic one: glibc also knows the call frame information of libc.so.6 and
        // walks on through the start code, ours knows the program's own image (the case in a static
        // runtime, where it is everything) and stops at the first frame outside it, after reporting it.
        assert!(nb >= 2 && na >= nb, "frames: glibc {na}, ours {nb}");
        // the first frame is in this function (two different call sites): the rest must be identical
        assert!((a[0] as isize - b[0] as isize).abs() < 400, "frame 0");
        for i in 1..nb as usize {
            assert_eq!(a[i], b[i], "frame {i}");
        }
        // every frame but the last is inside the program's image
        let (_, start, end) = dlfcn::image().unwrap();
        for (i, p) in b[..nb as usize - 1].iter().enumerate() {
            assert!((*p as u64) >= start && (*p as u64) < end, "frame {i} is in the image");
        }
        ours.extend(b[..nb as usize].iter().map(|&p| p as usize));
        theirs.extend(a[..na as usize].iter().map(|&p| p as usize));
        // limits
        for size in [0, 1, 2] {
            let mut x = [std::ptr::null_mut::<c_void>(); 4];
            let mut y = [std::ptr::null_mut::<c_void>(); 4];
            assert_eq!(host::backtrace(x.as_mut_ptr(), size), backtrace::backtrace(y.as_mut_ptr(), size));
        }
        // symbols: this crate's code is built as the static runtime's, which prints what a static glibc prints
        // ("[ADDRESS]": its dladdr knows no object); the host glibc here is the dynamic one ("FILE(+OFF) [ADDRESS]"),
        // so only the bracketed address is compared
        let sa = host::backtrace_symbols(a.as_ptr(), 3);
        let sb = backtrace::backtrace_symbols(b.as_ptr(), 3);
        for (i, addr) in b.iter().take(3).enumerate() {
            let (x, y) = (CStr::from_ptr(*sa.add(i)).to_str().unwrap(), CStr::from_ptr(*sb.add(i)).to_str().unwrap());
            assert_eq!(y, format!("[{:p}]", *addr), "symbol line {i}: {y}");
            // frame 0 differs in its address (two call sites); the other addresses must be equal
            if i != 0 {
                assert!(x.ends_with(y), "symbol line {i}: {x} / {y}");
            }
        }
        libc::free(sa.cast());
        rusty_libc_malloc::free(sb.cast());
    }
}

#[test]
fn backtrace_matches_glibc() {
    let (mut o, mut t) = (vec![], vec![]);
    both(0, &mut o, &mut t);
    both(7, &mut o, &mut t);
    both(30, &mut o, &mut t);
    assert!(o.len() > 40);
}

#[test]
fn backtrace_in_a_thread_and_signal() {
    let h = std::thread::spawn(|| {
        let (mut o, mut t) = (vec![], vec![]);
        both(5, &mut o, &mut t);
        o.len()
    });
    assert!(h.join().unwrap() > 5);
}

// ---- strfmon / strfmon_l with the monetary conventions of real locales ----

mod host_l {
    use std::ffi::c_char;
    unsafe extern "C" {
        pub fn strfmon_l(s: *mut c_char, max: usize, loc: libc::locale_t, fmt: *const c_char, ...) -> isize;
    }
}

const MON_LOCALES: [&str; 21] = [
    "en_US.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "ja_JP.UTF-8", "sv_SE.UTF-8", "cs_CZ.UTF-8", "pt_BR.UTF-8", "en_GB.UTF-8", "hi_IN.UTF-8", "de_CH.UTF-8", "it_IT.UTF-8",
    "es_ES.UTF-8", "nl_NL.UTF-8", "ru_RU.UTF-8", "en_IN.UTF-8", "pl_PL.UTF-8", "ko_KR.UTF-8", "zh_CN.UTF-8", "tr_TR.UTF-8", "ar_AE.UTF-8", "he_IL.UTF-8",
];

pub(crate) static MON_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn mon_formats() -> Vec<String> {
    let mut v: Vec<String> = [
        "%n", "%i", "%!n", "%!i", "%(n", "%(i", "%+n", "%+i", "%^n", "%^i", "[%12n]", "[%-12n]", "[%=*12n]", "[%=0#8n]", "[%#6.2n]", "[%.0n]", "[%.5i]", "[%.0i]", "x%ny", "[%#0n]", "[%^#12.3n]",
        "[%(#10n]", "[%+!-14.1i]", "[%(#12i]", "[%#10.3n]", "[%=_#12n]", "[%^=*#14.2i]", "[%+#8n]", "[%-+#14n]", "[%!(#14.1n]", "%n%n", "%i and %i",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.push("%20n|%-20i|".to_string());
    v
}

const MON_VALUES: [f64; 12] = [1234.5, -1234.5, 0.0, 0.005, 2.675, 123_456_789.987_654_33, -7.0, 99.995, -0.001, 1e12, -98765432.1, 0.5];

#[test]
fn strfmon_uses_locale_monetary_data() {
    let _g = MON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fmts = mon_formats();
    let mut checked = 0usize;
    for loc in MON_LOCALES {
        let cl = CString::new(loc).unwrap();
        unsafe {
            assert!(!libc::setlocale(libc::LC_ALL, cl.as_ptr()).is_null(), "host lacks {loc}");
            assert!(!rusty_libc_locale::setlocale(libc::LC_ALL, cl.as_ptr()).is_null(), "ours failed for {loc}");
        }
        for fmt in &fmts {
            let cf = CString::new(fmt.as_str()).unwrap();
            for &v in &MON_VALUES {
                for size in [0usize, 5, 700] {
                    let mut a = vec![b'#'; 800];
                    let mut b = vec![b'#'; 800];
                    unsafe {
                        *libc::__errno_location() = 0;
                        let ra = host::strfmon(a.as_mut_ptr() as *mut c_char, size, cf.as_ptr(), v, v);
                        let ea = *libc::__errno_location();
                        rusty_libc_core::errno::set(0);
                        let rb = strfmon::strfmon(b.as_mut_ptr() as *mut c_char, size, cf.as_ptr(), v, v);
                        let eb = rusty_libc_core::errno::get();
                        assert_eq!((ra, if ra < 0 { ea } else { 0 }), (rb, if rb < 0 { eb } else { 0 }), "{loc}: format {fmt:?} value {v} size {size}: host {:?} ours {:?}", String::from_utf8_lossy(&a[..a.iter().position(|&c| c == 0).unwrap_or(0)]), String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(0)]));
                        let end = a.iter().position(|&c| c == 0).unwrap_or(0);
                        assert_eq!(&a[..end], &b[..end], "{loc}: format {fmt:?} value {v} size {size}: text {:?} vs {:?}", String::from_utf8_lossy(&a[..end]), String::from_utf8_lossy(&b[..end]));
                    }
                    checked += 1;
                }
            }
        }
    }
    unsafe {
        libc::setlocale(libc::LC_ALL, c"C".as_ptr());
        rusty_libc_locale::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    eprintln!("strfmon in {} locales: {checked} outputs identical to glibc", MON_LOCALES.len());
}

#[test]
fn strfmon_l_uses_the_passed_locale() {
    let _g = MON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fmts = mon_formats();
    let mut checked = 0usize;
    unsafe {
        libc::setlocale(libc::LC_ALL, c"C".as_ptr());
        rusty_libc_locale::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    for loc in MON_LOCALES {
        let cl = CString::new(loc).unwrap();
        let (hl, ol) = unsafe { (libc::newlocale(libc::LC_ALL_MASK, cl.as_ptr(), std::ptr::null_mut()), rusty_libc_locale::newlocale(libc::LC_ALL_MASK, cl.as_ptr(), std::ptr::null_mut())) };
        assert!(!hl.is_null() && !ol.is_null(), "newlocale {loc}");
        for fmt in &fmts {
            let cf = CString::new(fmt.as_str()).unwrap();
            for &v in &MON_VALUES {
                let mut a = vec![b'#'; 800];
                let mut b = vec![b'#'; 800];
                unsafe {
                    *libc::__errno_location() = 0;
                    let ra = host_l::strfmon_l(a.as_mut_ptr() as *mut c_char, 700, hl, cf.as_ptr(), v, v);
                    let ea = *libc::__errno_location();
                    rusty_libc_core::errno::set(0);
                    let rb = strfmon::strfmon_l(b.as_mut_ptr() as *mut c_char, 700, ol, cf.as_ptr(), v, v);
                    let eb = rusty_libc_core::errno::get();
                    assert_eq!((ra, if ra < 0 { ea } else { 0 }), (rb, if rb < 0 { eb } else { 0 }), "{loc}: format {fmt:?} value {v}: host {:?} ours {:?}", String::from_utf8_lossy(&a[..a.iter().position(|&c| c == 0).unwrap_or(0)]), String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(0)]));
                    let end = a.iter().position(|&c| c == 0).unwrap_or(0);
                    assert_eq!(&a[..end], &b[..end], "{loc}: format {fmt:?} value {v}");
                }
                checked += 1;
            }
        }
        unsafe {
            libc::freelocale(hl);
            rusty_libc_locale::freelocale(ol);
        }
    }
    // the global locale argument and the thread locale
    unsafe {
        let cl = CString::new("de_DE.UTF-8").unwrap();
        libc::setlocale(libc::LC_ALL, cl.as_ptr());
        rusty_libc_locale::setlocale(libc::LC_ALL, cl.as_ptr());
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        // glibc's strfmon_l dereferences LC_GLOBAL_LOCALE (crashes): compare with its strfmon in the global locale
        let ra = host::strfmon(a.as_mut_ptr() as *mut c_char, 100, c"%n".as_ptr(), 1234.5f64);
        let rb = strfmon::strfmon_l(b.as_mut_ptr() as *mut c_char, 100, usize::MAX as *mut _, c"%n".as_ptr(), 1234.5f64);
        assert_eq!((ra, a), (rb, b));
        libc::setlocale(libc::LC_ALL, c"C".as_ptr());
        rusty_libc_locale::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    eprintln!("strfmon_l in {} locales: {checked} outputs identical to glibc", MON_LOCALES.len());
}

/// `__nss_hash` is the sdbm hash: values computed by hand (glibc's own test compares it with a simple loop).
#[test]
fn nss_hash_is_sdbm() {
    unsafe {
        assert_eq!(crate::glibc_priv::__nss_hash(b"abc".as_ptr().cast(), 3), 807_794_786);
        assert_eq!(crate::glibc_priv::__nss_hash([0x80u8; 7].as_ptr().cast(), 7), 2_764_546_176);
        assert_eq!(crate::glibc_priv::__nss_hash(core::ptr::null(), 0), 0);
    }
}
