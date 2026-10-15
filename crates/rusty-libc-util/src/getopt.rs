#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;

use crate::cmem;
use crate::err::{Out, name_bytes};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

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

static STATE: SyncCell<Data> = SyncCell::new(Data::new());

struct Args<'a> {
    v: &'a mut [*mut c_char],
}

impl<'a> Args<'a> {
    unsafe fn new(v: &'a mut [*mut c_char]) -> Args<'a> {
        Args { v }
    }
    #[inline]
    fn argc(&self) -> c_int {
        self.v.len() as c_int
    }
    #[inline]
    fn ptr(&self, i: c_int) -> *mut c_char {
        usize::try_from(i).ok().and_then(|i| self.v.get(i)).copied().unwrap_or(null_mut())
    }
    #[inline]
    fn byte(&self, i: c_int, k: usize) -> u8 {
        let p = self.ptr(i);
        if p.is_null() {
            return 0;
        }
        unsafe { cstr_at(p, k) }
    }
    #[inline]
    fn prog(&self) -> &'a [u8] {
        unsafe { name_bytes(self.v[0]) }
    }
    #[inline]
    fn swap(&mut self, a: c_int, b: c_int) {
        self.v.swap(a as usize, b as usize);
    }
}

#[derive(Clone, Copy)]
struct LongOpts<'a> {
    p: *const COption,
    _t: core::marker::PhantomData<&'a [COption]>,
}

impl<'a> LongOpts<'a> {
    unsafe fn new(p: *const COption) -> Option<LongOpts<'a>> {
        if p.is_null() { None } else { Some(LongOpts { p, _t: core::marker::PhantomData }) }
    }
    fn exact(&self, name: &[u8]) -> Result<(usize, Table<'a>), Table<'a>> {
        let mut n = 0;
        loop {
            let e = unsafe { &*self.p.wrapping_add(n) };
            if e.name.is_null() {
                return Err(Table { o: unsafe { ffi::slice(self.p, n) } });
            }
            let t = Table { o: core::slice::from_ref(e) };
            if t.matches(0, name) == Some(true) {
                return Ok((n, Table { o: unsafe { ffi::slice(self.p, n + 1) } }));
            }
            n += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct Table<'a> {
    o: &'a [COption],
}

impl<'a> Table<'a> {
    #[inline]
    fn matches(&self, i: usize, name: &[u8]) -> Option<bool> {
        let p = self.o[i].name;
        for (k, &c) in name.iter().enumerate() {
            if unsafe { cbyte(p, k) } != c {
                return None;
            }
        }
        Some(unsafe { cbyte(p, name.len()) } == 0)
    }
    #[inline]
    fn name(&self, i: usize) -> &'a [u8] {
        unsafe { ffi::cstr_bytes(self.o[i].name) }
    }
}

#[inline]
unsafe fn cbyte(p: *const c_char, k: usize) -> u8 {
    unsafe { *p.cast::<u8>().wrapping_add(k) }
}

#[inline]
unsafe fn cstr_at(p: *const c_char, i: usize) -> u8 {
    for k in 0..i {
        if unsafe { cbyte(p, k) } == 0 {
            return 0;
        }
    }
    unsafe { cbyte(p, i) }
}

#[derive(Clone, Copy)]
struct OptStr<'a> {
    p: *const c_char,
    _s: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> OptStr<'a> {
    unsafe fn new(p: *const c_char) -> OptStr<'a> {
        OptStr { p, _s: core::marker::PhantomData }
    }
    #[inline]
    fn at(&self, i: usize) -> u8 {
        unsafe { cstr_at(self.p, i) }
    }
    #[inline]
    fn skip1(self) -> OptStr<'a> {
        debug_assert!(self.at(0) != 0);
        OptStr { p: self.p.wrapping_add(1), _s: self._s }
    }
    #[inline]
    fn find(&self, c: u8) -> Option<usize> {
        let mut k = 0;
        loop {
            let b = unsafe { cbyte(self.p, k) };
            if b == c {
                return Some(k);
            }
            if b == 0 {
                return None;
            }
            k += 1;
        }
    }
    #[inline]
    fn find_rest(&self, c: u8) -> Option<OptStr<'a>> {
        let k = self.find(c)?;
        let after = if c == 0 { k } else { k + 1 };
        Some(OptStr { p: self.p.wrapping_add(after), _s: self._s })
    }
    #[inline]
    fn has(&self, c: u8) -> bool {
        self.find(c).is_some()
    }
}

#[inline]
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

#[inline]
fn next_bytes<'a>(d: &Data) -> &'a [u8] {
    debug_assert!(!d.nextchar.is_null());
    unsafe { ffi::cstr_bytes(d.nextchar) }
}

fn exchange(argv: &mut Args, d: &mut Data) {
    let mut bottom = d.first_nonopt;
    let middle = d.last_nonopt;
    let mut top = d.optind;
    while top > middle && middle > bottom {
        if top - middle > middle - bottom {
            let len = middle - bottom;
            for i in 0..len {
                argv.swap(bottom + i, top - (middle - bottom) + i);
            }
            top -= len;
        } else {
            let len = top - middle;
            for i in 0..len {
                argv.swap(bottom + i, middle + i);
            }
            bottom += len;
        }
    }
    d.first_nonopt += d.optind - d.last_nonopt;
    d.last_nonopt = d.optind;
}

fn say(argv0: *const c_char, prog: &[u8], msgid: &'static CStr, args: &[u64], parts: &[&[u8]]) {
    if say_tr1(argv0, msgid, args) {
        return;
    }
    let mut o = Out::new();
    o.bytes(prog);
    for p in parts {
        o.bytes(p);
    }
    o.flush();
}

fn say_tr(o: &mut Out, msgid: &'static CStr, args: &[u64]) -> bool {
    rusty_libc_core::i18n::tr_format(msgid, args, &mut |b: &[u8]| o.bytes(b))
}

fn prefix_c(prefix: &[u8]) -> u64 {
    (match prefix {
        b"--" => c"--",
        b"-W " => c"-W ",
        _ => c"-",
    })
    .as_ptr() as u64
}

fn say_tr1(argv0: *const c_char, msgid: &'static CStr, args: &[u64]) -> bool {
    let mut all = [0u64; 4];
    all[0] = argv0 as u64;
    all[1..1 + args.len()].copy_from_slice(args);
    let mut o = Out::new();
    if say_tr(&mut o, msgid, &all[..1 + args.len()]) {
        o.flush();
        true
    } else {
        false
    }
}

struct Scan<'a, 'b> {
    argv: Args<'a>,
    optstring: OptStr<'a>,
    longopts: Option<LongOpts<'a>>,
    longind: Option<&'b mut c_int>,
    long_only: bool,
    print_errors: bool,
}

fn process_long_option(sc: &mut Scan, d: &mut Data, long_only: bool, prefix: &[u8]) -> c_int {
    let Some(lo) = sc.longopts else { return -1 };
    let next_p = d.nextchar;
    let next = next_bytes(d);
    let namelen = next.iter().position(|&c| c == b'=').unwrap_or(next.len());
    let name = &next[..namelen];
    let argv0 = sc.argv.ptr(0);

    let mut pfound: Option<usize> = None;
    let mut option_index: c_int = 0;
    let lo = match lo.exact(name) {
        Ok((i, t)) => {
            pfound = Some(i);
            option_index = i as c_int;
            t
        }
        Err(t) => t,
    };
    let n_options = lo.o.len();

    if pfound.is_none() {
        let mut ambig_set: *mut u8 = null_mut();
        let mut ambig: &mut [u8] = &mut [];
        let mut ambig_fallback = false;
        let mut indfound: c_int = -1;
        for idx in 0..n_options {
            if lo.matches(idx, name).is_some() {
                match pfound {
                    None => {
                        pfound = Some(idx);
                        indfound = idx as c_int;
                    }
                    Some(f) => {
                        let (pf, p) = (&lo.o[f], &lo.o[idx]);
                        if (long_only || pf.has_arg != p.has_arg || pf.flag != p.flag || pf.val != p.val) && !ambig_fallback {
                            if !sc.print_errors {
                                ambig_fallback = true;
                            } else if ambig_set.is_null() {
                                ambig_set = cmem::malloc(n_options.max(1));
                                if ambig_set.is_null() {
                                    ambig_fallback = true;
                                } else {
                                    ambig = unsafe { ffi::bytes_mut(ambig_set, n_options) };
                                    ambig.fill(0);
                                    ambig[indfound as usize] = 1;
                                }
                            }
                            if !ambig_set.is_null() {
                                ambig[idx] = 1;
                            }
                        }
                    }
                }
            }
        }
        if !ambig_set.is_null() || ambig_fallback {
            if sc.print_errors {
                let mut o = Out::new();
                let targs = [argv0 as u64, prefix_c(prefix), next_p as u64];
                if ambig_fallback {
                    if !say_tr(&mut o, c"%s: option '%s%s' is ambiguous\n", &targs) {
                        o.bytes(sc.argv.prog());
                        o.bytes(b": option '");
                        o.bytes(prefix);
                        o.bytes(next);
                        o.bytes(b"' is ambiguous\n");
                    }
                } else {
                    if !say_tr(&mut o, c"%s: option '%s%s' is ambiguous; possibilities:", &targs) {
                        o.bytes(sc.argv.prog());
                        o.bytes(b": option '");
                        o.bytes(prefix);
                        o.bytes(next);
                        o.bytes(b"' is ambiguous; possibilities:");
                    }
                    for (i, &a) in ambig.iter().enumerate() {
                        if a != 0 {
                            o.bytes(b" '");
                            o.bytes(prefix);
                            o.bytes(lo.name(i));
                            o.bytes(b"'");
                        }
                    }
                    o.bytes(b"\n");
                }
                o.flush();
            }
            unsafe { cmem::free(ambig_set) };
            d.nextchar = d.nextchar.wrapping_add(next.len());
            d.optind += 1;
            d.optopt = 0;
            return b'?' as c_int;
        }
        option_index = indfound;
    }

    let Some(pi) = pfound else {
        if !long_only || sc.argv.byte(d.optind, 1) == b'-' || !sc.optstring.has(at(next, 0)) {
            if sc.print_errors {
                say(argv0, sc.argv.prog(), c"%s: unrecognized option '%s%s'\n", &[prefix_c(prefix), next_p as u64], &[b": unrecognized option '", prefix, next, b"'\n"]);
            }
            d.nextchar = null_mut();
            d.optind += 1;
            d.optopt = 0;
            return b'?' as c_int;
        }
        return -1;
    };

    let pf = lo.o[pi];
    d.optind += 1;
    d.nextchar = null_mut();
    if namelen < next.len() {
        if pf.has_arg != 0 {
            d.optarg = next_p.wrapping_add(namelen + 1);
        } else {
            if sc.print_errors {
                say(argv0, sc.argv.prog(), c"%s: option '%s%s' doesn't allow an argument\n", &[prefix_c(prefix), pf.name as u64], &[b": option '", prefix, lo.name(pi), b"' doesn't allow an argument\n"]);
            }
            d.optopt = pf.val;
            return b'?' as c_int;
        }
    } else if pf.has_arg == 1 {
        if d.optind < sc.argv.argc() {
            d.optarg = sc.argv.ptr(d.optind);
            d.optind += 1;
        } else {
            if sc.print_errors {
                say(argv0, sc.argv.prog(), c"%s: option '%s%s' requires an argument\n", &[prefix_c(prefix), pf.name as u64], &[b": option '", prefix, lo.name(pi), b"' requires an argument\n"]);
            }
            d.optopt = pf.val;
            return if sc.optstring.at(0) == b':' { b':' as c_int } else { b'?' as c_int };
        }
    }
    if let Some(li) = sc.longind.as_deref_mut() {
        *li = option_index;
    }
    if !pf.flag.is_null() {
        unsafe { *pf.flag = pf.val };
        return 0;
    }
    pf.val
}

fn initialize<'a>(optstring: OptStr<'a>, d: &mut Data, posixly_correct: bool) -> OptStr<'a> {
    let mut os = optstring;
    if d.optind == 0 {
        d.optind = 1;
    }
    d.first_nonopt = d.optind;
    d.last_nonopt = d.optind;
    d.nextchar = null_mut();
    if os.at(0) == b'-' {
        d.ordering = RETURN_IN_ORDER;
        os = os.skip1();
    } else if os.at(0) == b'+' {
        d.ordering = REQUIRE_ORDER;
        os = os.skip1();
    } else if posixly_correct || crate::cmem::getenv(b"POSIXLY_CORRECT").is_some() {
        d.ordering = REQUIRE_ORDER;
    } else {
        d.ordering = PERMUTE;
    }
    d.initialized = 1;
    os
}

fn scan(sc: &mut Scan, d: &mut Data, posixly_correct: bool) -> c_int {
    let argc = sc.argv.argc();
    d.optarg = null_mut();
    if d.optind == 0 || d.initialized == 0 {
        sc.optstring = initialize(sc.optstring, d, posixly_correct);
    } else if sc.optstring.at(0) == b'-' || sc.optstring.at(0) == b'+' {
        sc.optstring = sc.optstring.skip1();
    }
    if sc.optstring.at(0) == b':' {
        sc.print_errors = false;
    }

    let nonoption = |argv: &Args, d: &Data| {
        argv.byte(d.optind, 0) != b'-' || argv.byte(d.optind, 1) == 0
    };

    if d.nextchar.is_null() || unsafe { cbyte(d.nextchar, 0) } == 0 {
        if d.last_nonopt > d.optind {
            d.last_nonopt = d.optind;
        }
        if d.first_nonopt > d.optind {
            d.first_nonopt = d.optind;
        }
        if d.ordering == PERMUTE {
            if d.first_nonopt != d.last_nonopt && d.last_nonopt != d.optind {
                exchange(&mut sc.argv, d);
            } else if d.last_nonopt != d.optind {
                d.first_nonopt = d.optind;
            }
            while d.optind < argc && nonoption(&sc.argv, d) {
                d.optind += 1;
            }
            d.last_nonopt = d.optind;
        }
        if d.optind != argc && sc.argv.byte(d.optind, 0) == b'-' && sc.argv.byte(d.optind, 1) == b'-' && sc.argv.byte(d.optind, 2) == 0 {
            d.optind += 1;
            if d.first_nonopt != d.last_nonopt && d.last_nonopt != d.optind {
                exchange(&mut sc.argv, d);
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
        if nonoption(&sc.argv, d) {
            if d.ordering == REQUIRE_ORDER {
                return -1;
            }
            d.optarg = sc.argv.ptr(d.optind);
            d.optind += 1;
            return 1;
        }
        if sc.longopts.is_some() {
            let ap = sc.argv.ptr(d.optind);
            if sc.argv.byte(d.optind, 1) == b'-' {
                d.nextchar = ap.wrapping_add(2);
                return process_long_option(sc, d, sc.long_only, b"--");
            }
            if sc.long_only && (sc.argv.byte(d.optind, 2) != 0 || !sc.optstring.has(sc.argv.byte(d.optind, 1))) {
                d.nextchar = ap.wrapping_add(1);
                let code = process_long_option(sc, d, sc.long_only, b"-");
                if code != -1 {
                    return code;
                }
            }
        }
        d.nextchar = sc.argv.ptr(d.optind).wrapping_add(1);
    }

    let argv0 = sc.argv.ptr(0);
    let mut c = unsafe { cbyte(d.nextchar, 0) };
    let rest_empty = c == 0 || unsafe { cbyte(d.nextchar, 1) } == 0;
    d.nextchar = d.nextchar.wrapping_add(1);
    let temp = sc.optstring.find_rest(c);
    if rest_empty {
        d.optind += 1;
    }
    let Some(spec) = temp.filter(|_| c != b':' && c != b';') else {
        if sc.print_errors {
            say(argv0, sc.argv.prog(), c"%s: invalid option -- '%c'\n", &[u64::from(c)], &[b": invalid option -- '", &[c], b"'\n"]);
        }
        d.optopt = c as c_int;
        return b'?' as c_int;
    };

    if c == b'W' && spec.at(0) == b';' && sc.longopts.is_some() {
        if !rest_empty {
            d.optarg = d.nextchar;
        } else if d.optind == argc {
            if sc.print_errors {
                say(argv0, sc.argv.prog(), c"%s: option requires an argument -- '%c'\n", &[u64::from(c)], &[b": option requires an argument -- '", &[c], b"'\n"]);
            }
            d.optopt = c as c_int;
            return if sc.optstring.at(0) == b':' { b':' as c_int } else { b'?' as c_int };
        } else {
            d.optarg = sc.argv.ptr(d.optind);
        }
        d.nextchar = d.optarg;
        d.optarg = null_mut();
        return process_long_option(sc, d, false, b"-W ");
    }
    if spec.at(0) == b':' {
        if spec.at(1) == b':' {
            if !rest_empty {
                d.optarg = d.nextchar;
                d.optind += 1;
            } else {
                d.optarg = null_mut();
            }
            d.nextchar = null_mut();
        } else {
            if !rest_empty {
                d.optarg = d.nextchar;
                d.optind += 1;
            } else if d.optind == argc {
                if sc.print_errors {
                    say(argv0, sc.argv.prog(), c"%s: option requires an argument -- '%c'\n", &[u64::from(c)], &[b": option requires an argument -- '", &[c], b"'\n"]);
                }
                d.optopt = c as c_int;
                c = if sc.optstring.at(0) == b':' { b':' } else { b'?' };
            } else {
                d.optarg = sc.argv.ptr(d.optind);
                d.optind += 1;
            }
            d.nextchar = null_mut();
        }
    }
    c as c_int
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
    if argc < 1 {
        return -1;
    }
    let v = unsafe { ffi::slice_mut(argv, argc as usize) };
    let mut sc = Scan {
        argv: unsafe { Args::new(v) },
        optstring: unsafe { OptStr::new(optstring) },
        longopts: unsafe { LongOpts::new(longopts) },
        longind: unsafe { ffi::out(longind) },
        long_only,
        print_errors: d.opterr != 0,
    };
    scan(&mut sc, d, posixly_correct)
}

unsafe fn internal(argc: c_int, argv: *mut *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int, long_only: bool, posixly: bool) -> c_int {
    let st = unsafe { &mut *STATE.as_ptr() };
    st.optind = unsafe { optind };
    st.opterr = unsafe { opterr };
    let r = unsafe { getopt_internal_r(argc, argv, optstring, longopts, longind, long_only, st, posixly) };
    unsafe { optind = st.optind };
    unsafe { optarg = st.optarg };
    unsafe { optopt = st.optopt };
    r
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
