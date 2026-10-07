use core::ffi::{c_char, c_int};
use core::ptr::null_mut;

use crate::err::{Out, name_bytes};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct COption {
    pub name: *const c_char,
    pub has_arg: c_int,
    pub flag: *mut c_int,
    pub val: c_int,
}

pub const NO_ARGUMENT: c_int = 0;
pub const REQUIRED_ARGUMENT: c_int = 1;
pub const OPTIONAL_ARGUMENT: c_int = 2;

const REQUIRE_ORDER: c_int = 0;
const PERMUTE: c_int = 1;
const RETURN_IN_ORDER: c_int = 2;

#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut optarg: *mut c_char = null_mut();
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut optind: c_int = 1;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut opterr: c_int = 1;
#[allow(non_upper_case_globals)]
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static mut optopt: c_int = b'?' as c_int;

#[repr(C)]
pub struct Data {
    pub optind: c_int,
    pub opterr: c_int,
    pub optopt: c_int,
    pub optarg: *mut c_char,
    initialized: c_int,
    nextchar: *mut c_char,
    ordering: c_int,
    first_nonopt: c_int,
    last_nonopt: c_int,
}

impl Data {
    pub const fn new() -> Data {
        Data { optind: 1, opterr: 1, optopt: 0, optarg: null_mut(), initialized: 0, nextchar: null_mut(), ordering: PERMUTE, first_nonopt: 0, last_nonopt: 0 }
    }
    pub fn reset(&mut self) {
        self.optind = 0;
    }
}

impl Default for Data {
    fn default() -> Self {
        Data::new()
    }
}

static mut STATE: Data = Data::new();

unsafe fn arg(argv: *mut *mut c_char, i: c_int) -> *mut c_char {
    unsafe { *argv.add(i as usize) }
}

unsafe fn byte(p: *const c_char, i: usize) -> u8 {
    unsafe { *(p as *const u8).add(i) }
}

unsafe fn exchange(argv: *mut *mut c_char, d: &mut Data) {
    unsafe {
        let mut bottom = d.first_nonopt;
        let middle = d.last_nonopt;
        let mut top = d.optind;
        while top > middle && middle > bottom {
            if top - middle > middle - bottom {
                let len = middle - bottom;
                for i in 0..len {
                    let a = argv.add((bottom + i) as usize);
                    let b = argv.add((top - (middle - bottom) + i) as usize);
                    core::ptr::swap(a, b);
                }
                top -= len;
            } else {
                let len = top - middle;
                for i in 0..len {
                    let a = argv.add((bottom + i) as usize);
                    let b = argv.add((middle + i) as usize);
                    core::ptr::swap(a, b);
                }
                bottom += len;
            }
        }
        d.first_nonopt += d.optind - d.last_nonopt;
        d.last_nonopt = d.optind;
    }
}

unsafe fn name_has_prefix(name: *const c_char, text: *const c_char, n: usize) -> bool {
    unsafe {
        for i in 0..n {
            let c = byte(name, i);
            if c == 0 || c != byte(text, i) {
                return false;
            }
        }
        true
    }
}

unsafe fn cstr_len(p: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(p.cast()) }
}

unsafe fn say(argv0: *const c_char, parts: &[&[u8]]) {
    unsafe {
        let mut o = Out::new();
        o.bytes(name_bytes(argv0));
        for p in parts {
            o.bytes(p);
        }
        o.flush();
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn process_long_option(
    argc: c_int,
    argv: *mut *mut c_char,
    optstring: *const c_char,
    longopts: *const COption,
    longind: *mut c_int,
    long_only: bool,
    d: &mut Data,
    print_errors: bool,
    prefix: &[u8],
) -> c_int {
    unsafe {
        let next = d.nextchar;
        let mut nameend = next;
        while *nameend != 0 && *nameend != b'=' as c_char {
            nameend = nameend.add(1);
        }
        let namelen = nameend as usize - next as usize;
        let next_bytes = |extra: usize| core::slice::from_raw_parts(next as *const u8, cstr_len(next) + extra);

        let mut n_options = 0usize;
        let mut pfound: *const COption = core::ptr::null();
        let mut option_index: c_int = 0;
        let mut p = longopts;
        while !(*p).name.is_null() {
            if name_has_prefix((*p).name, next, namelen) && cstr_len((*p).name) == namelen {
                pfound = p;
                option_index = n_options as c_int;
                break;
            }
            p = p.add(1);
            n_options += 1;
        }

        if pfound.is_null() {
            let mut ambig_set: *mut u8 = null_mut();
            let mut ambig_fallback = false;
            let mut indfound: c_int = -1;
            let mut idx = 0usize;
            let mut p = longopts;
            while !(*p).name.is_null() {
                if name_has_prefix((*p).name, next, namelen) {
                    if pfound.is_null() {
                        pfound = p;
                        indfound = idx as c_int;
                    } else if (long_only || (*pfound).has_arg != (*p).has_arg || (*pfound).flag != (*p).flag || (*pfound).val != (*p).val) && !ambig_fallback {
                        if !print_errors {
                            ambig_fallback = true;
                        } else if ambig_set.is_null() {
                            ambig_set = rusty_libc_malloc::malloc(n_options.max(1)) as *mut u8;
                            if ambig_set.is_null() {
                                ambig_fallback = true;
                            } else {
                                core::ptr::write_bytes(ambig_set, 0, n_options);
                                *ambig_set.add(indfound as usize) = 1;
                            }
                        }
                        if !ambig_set.is_null() {
                            *ambig_set.add(idx) = 1;
                        }
                    }
                }
                p = p.add(1);
                idx += 1;
            }
            if !ambig_set.is_null() || ambig_fallback {
                if print_errors {
                    let mut o = Out::new();
                    o.bytes(name_bytes(*argv));
                    o.bytes(b": option '");
                    o.bytes(prefix);
                    o.bytes(next_bytes(0));
                    if ambig_fallback {
                        o.bytes(b"' is ambiguous\n");
                    } else {
                        o.bytes(b"' is ambiguous; possibilities:");
                        for i in 0..n_options {
                            if *ambig_set.add(i) != 0 {
                                o.bytes(b" '");
                                o.bytes(prefix);
                                o.bytes(name_bytes((*longopts.add(i)).name));
                                o.bytes(b"'");
                            }
                        }
                        o.bytes(b"\n");
                    }
                    o.flush();
                }
                if !ambig_set.is_null() {
                    rusty_libc_malloc::free(ambig_set.cast());
                }
                d.nextchar = d.nextchar.add(cstr_len(d.nextchar));
                d.optind += 1;
                d.optopt = 0;
                return b'?' as c_int;
            }
            option_index = indfound;
        }

        if pfound.is_null() {
            if !long_only || byte(arg(argv, d.optind), 1) == b'-' || rusty_libc_mem::strchr(optstring.cast(), *d.nextchar as u8 as c_int).is_null() {
                if print_errors {
                    say(*argv, &[b": unrecognized option '", prefix, next_bytes(0), b"'\n"]);
                }
                d.nextchar = null_mut();
                d.optind += 1;
                d.optopt = 0;
                return b'?' as c_int;
            }
            return -1;
        }

        let pf = &*pfound;
        d.optind += 1;
        d.nextchar = null_mut();
        if *nameend != 0 {
            if pf.has_arg != 0 {
                d.optarg = nameend.add(1);
            } else {
                if print_errors {
                    say(*argv, &[b": option '", prefix, name_bytes(pf.name), b"' doesn't allow an argument\n"]);
                }
                d.optopt = pf.val;
                return b'?' as c_int;
            }
        } else if pf.has_arg == 1 {
            if d.optind < argc {
                d.optarg = arg(argv, d.optind);
                d.optind += 1;
            } else {
                if print_errors {
                    say(*argv, &[b": option '", prefix, name_bytes(pf.name), b"' requires an argument\n"]);
                }
                d.optopt = pf.val;
                return if byte(optstring, 0) == b':' { b':' as c_int } else { b'?' as c_int };
            }
        }
        if !longind.is_null() {
            *longind = option_index;
        }
        if !pf.flag.is_null() {
            *pf.flag = pf.val;
            return 0;
        }
        pf.val
    }
}

unsafe fn initialize(optstring: *const c_char, d: &mut Data, posixly_correct: bool) -> *const c_char {
    unsafe {
        let mut os = optstring;
        if d.optind == 0 {
            d.optind = 1;
        }
        d.first_nonopt = d.optind;
        d.last_nonopt = d.optind;
        d.nextchar = null_mut();
        if byte(os, 0) == b'-' {
            d.ordering = RETURN_IN_ORDER;
            os = os.add(1);
        } else if byte(os, 0) == b'+' {
            d.ordering = REQUIRE_ORDER;
            os = os.add(1);
        } else if posixly_correct || !rusty_libc_core::env::getenv(b"POSIXLY_CORRECT").is_null() {
            d.ordering = REQUIRE_ORDER;
        } else {
            d.ordering = PERMUTE;
        }
        d.initialized = 1;
        os
    }
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn getopt_internal_r(
    argc: c_int,
    argv: *mut *mut c_char,
    optstring: *const c_char,
    longopts: *const COption,
    longind: *mut c_int,
    long_only: bool,
    d: &mut Data,
    posixly_correct: bool,
) -> c_int {
    unsafe {
        let mut print_errors = d.opterr != 0;
        if argc < 1 {
            return -1;
        }
        d.optarg = null_mut();
        let mut optstring = optstring;
        if d.optind == 0 || d.initialized == 0 {
            optstring = initialize(optstring, d, posixly_correct);
        } else if byte(optstring, 0) == b'-' || byte(optstring, 0) == b'+' {
            optstring = optstring.add(1);
        }
        if byte(optstring, 0) == b':' {
            print_errors = false;
        }

        let nonoption = |d: &Data| byte(arg(argv, d.optind), 0) != b'-' || byte(arg(argv, d.optind), 1) == 0;

        if d.nextchar.is_null() || *d.nextchar == 0 {
            if d.last_nonopt > d.optind {
                d.last_nonopt = d.optind;
            }
            if d.first_nonopt > d.optind {
                d.first_nonopt = d.optind;
            }
            if d.ordering == PERMUTE {
                if d.first_nonopt != d.last_nonopt && d.last_nonopt != d.optind {
                    exchange(argv, d);
                } else if d.last_nonopt != d.optind {
                    d.first_nonopt = d.optind;
                }
                while d.optind < argc && nonoption(d) {
                    d.optind += 1;
                }
                d.last_nonopt = d.optind;
            }
            if d.optind != argc && rusty_libc_mem::strcmp(arg(argv, d.optind).cast(), c"--".as_ptr().cast()) == 0 {
                d.optind += 1;
                if d.first_nonopt != d.last_nonopt && d.last_nonopt != d.optind {
                    exchange(argv, d);
                } else if d.first_nonopt == d.last_nonopt {
                    d.first_nonopt = d.optind;
                }
                d.last_nonopt = argc;
                d.optind = argc;
            }
            if d.optind == argc {
                if d.first_nonopt != d.last_nonopt {
                    d.optind = d.first_nonopt;
                }
                return -1;
            }
            if nonoption(d) {
                if d.ordering == REQUIRE_ORDER {
                    return -1;
                }
                d.optarg = arg(argv, d.optind);
                d.optind += 1;
                return 1;
            }
            if !longopts.is_null() {
                let a = arg(argv, d.optind);
                if byte(a, 1) == b'-' {
                    d.nextchar = a.add(2);
                    return process_long_option(argc, argv, optstring, longopts, longind, long_only, d, print_errors, b"--");
                }
                if long_only && (byte(a, 2) != 0 || rusty_libc_mem::strchr(optstring.cast(), byte(a, 1) as c_int).is_null()) {
                    d.nextchar = a.add(1);
                    let code = process_long_option(argc, argv, optstring, longopts, longind, long_only, d, print_errors, b"-");
                    if code != -1 {
                        return code;
                    }
                }
            }
            d.nextchar = arg(argv, d.optind).add(1);
        }

        let mut c = *d.nextchar as u8;
        d.nextchar = d.nextchar.add(1);
        let temp = rusty_libc_mem::strchr(optstring.cast(), c as c_int) as *const c_char;
        if *d.nextchar == 0 {
            d.optind += 1;
        }
        if temp.is_null() || c == b':' || c == b';' {
            if print_errors {
                say(*argv, &[b": invalid option -- '", &[c], b"'\n"]);
            }
            d.optopt = c as c_int;
            return b'?' as c_int;
        }

        if byte(temp, 0) == b'W' && byte(temp, 1) == b';' && !longopts.is_null() {
            if *d.nextchar != 0 {
                d.optarg = d.nextchar;
            } else if d.optind == argc {
                if print_errors {
                    say(*argv, &[b": option requires an argument -- '", &[c], b"'\n"]);
                }
                d.optopt = c as c_int;
                return if byte(optstring, 0) == b':' { b':' as c_int } else { b'?' as c_int };
            } else {
                d.optarg = arg(argv, d.optind);
            }
            d.nextchar = d.optarg;
            d.optarg = null_mut();
            return process_long_option(argc, argv, optstring, longopts, longind, false, d, print_errors, b"-W ");
        }
        if byte(temp, 1) == b':' {
            if byte(temp, 2) == b':' {
                if *d.nextchar != 0 {
                    d.optarg = d.nextchar;
                    d.optind += 1;
                } else {
                    d.optarg = null_mut();
                }
                d.nextchar = null_mut();
            } else {
                if *d.nextchar != 0 {
                    d.optarg = d.nextchar;
                    d.optind += 1;
                } else if d.optind == argc {
                    if print_errors {
                        say(*argv, &[b": option requires an argument -- '", &[c], b"'\n"]);
                    }
                    d.optopt = c as c_int;
                    c = if byte(optstring, 0) == b':' { b':' } else { b'?' };
                } else {
                    d.optarg = arg(argv, d.optind);
                    d.optind += 1;
                }
                d.nextchar = null_mut();
            }
        }
        c as c_int
    }
}

unsafe fn internal(argc: c_int, argv: *mut *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int, long_only: bool, posixly: bool) -> c_int {
    unsafe {
        let st = &mut *(&raw mut STATE);
        st.optind = optind;
        st.opterr = opterr;
        let r = getopt_internal_r(argc, argv, optstring, longopts, longind, long_only, st, posixly);
        optind = st.optind;
        optarg = st.optarg;
        optopt = st.optopt;
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int {
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, core::ptr::null(), null_mut(), false, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __posix_getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int {
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, core::ptr::null(), null_mut(), false, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long(argc: c_int, argv: *const *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int) -> c_int {
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, longopts, longind, false, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long_only(argc: c_int, argv: *const *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int) -> c_int {
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, longopts, longind, true, false) }
}
