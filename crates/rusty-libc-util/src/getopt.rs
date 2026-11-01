//! getopt.h: `getopt`, `getopt_long`, `getopt_long_only` and the globals `optarg`, `optind`,
//! `opterr`, `optopt`.
//!
//! Behaviour follows glibc 2.43 (the GNU getopt): `argv` is permuted so options come first unless
//! the option string starts with `+` or `POSIXLY_CORRECT` is set; a leading `-` returns every
//! non-option as the argument of option 1; `optind = 0` (or an `optstring` first seen) restarts the
//! scan; long options may be abbreviated when unambiguous (two matches with the same `has_arg`,
//! `flag` and `val` are not ambiguous, except in `getopt_long_only`); `-W foo` means `--foo` when the
//! option string has `W;`; the error messages go to `stderr` as `argv[0]: ...` unless `opterr` is 0
//! or the option string starts with `:`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char, c_int};
use core::ptr::null_mut;

use crate::cmem;
use crate::err::{Out, name_bytes};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

/// `struct option` from getopt.h.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct COption {
    pub name: *const c_char,
    /// `no_argument` = 0, `required_argument` = 1, `optional_argument` = 2.
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

// The four globals. glibc's names are `optarg`, `optind`, `opterr`, `optopt`. They stay `static mut`: they are C data
// symbols that programs read and write directly, and tools/hdrgen declares them in getopt.h/unistd.h from these items.
// Rule: getopt is MT-Unsafe (glibc: race:getopt), so the program does not scan from two threads at once; `internal` is the
// only Rust code that touches them.
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

/// The scanner state of one argument vector (glibc's `struct _getopt_data`): the Rust API for
/// parsing several vectors at once or inside code that must not touch the global variables.
#[repr(C)]
pub struct Data {
    pub optind: c_int,
    pub opterr: c_int,
    pub optopt: c_int,
    pub optarg: *mut c_char,
    initialized: c_int,
    /// NULL or a position inside one of the strings of the argument vector being scanned (only the scanner sets it).
    nextchar: *mut c_char,
    ordering: c_int,
    first_nonopt: c_int,
    last_nonopt: c_int,
}

impl Data {
    /// A fresh state: `optind` 1, errors printed.
    pub const fn new() -> Data {
        Data { optind: 1, opterr: 1, optopt: 0, optarg: null_mut(), initialized: 0, nextchar: null_mut(), ordering: PERMUTE, first_nonopt: 0, last_nonopt: 0 }
    }
    /// Restart the scan (like setting `optind` to 0).
    pub fn reset(&mut self) {
        self.optind = 0;
    }
}

impl Default for Data {
    fn default() -> Self {
        Data::new()
    }
}

/// The state of the global scanner (glibc's `getopt_data`), under the rule of the globals above.
static STATE: SyncCell<Data> = SyncCell::new(Data::new());

/// The argument vector of one call: `argc` pointers, each NULL or a C string.
struct Args<'a> {
    v: &'a mut [*mut c_char],
}

impl<'a> Args<'a> {
    /// # Safety
    /// Every element of `v` is NULL or a C string that stays valid and unchanged for `'a` (getopt only permutes the
    /// pointers, never the strings).
    unsafe fn new(v: &'a mut [*mut c_char]) -> Args<'a> {
        Args { v }
    }
    #[inline]
    fn argc(&self) -> c_int {
        self.v.len() as c_int
    }
    /// `argv[i]`; NULL for an index outside the vector (glibc would read past it: a program that sets `optind` beyond
    /// `argc`).
    #[inline]
    fn ptr(&self, i: c_int) -> *mut c_char {
        // (a negative index becomes one of at least 2^31, past any vector `argc` can describe: None as well)
        self.v.get(i as u32 as usize).copied().unwrap_or(null_mut())
    }
    /// Byte `k` of `argv[i]`, 0 at or past its NUL (NULL reads as empty).
    #[inline]
    fn byte(&self, i: c_int, k: usize) -> u8 {
        let p = self.ptr(i);
        if p.is_null() {
            return 0;
        }
        // SAFETY: `p` is a C string valid for `'a` (`new`'s contract).
        unsafe { cstr_at(p, k) }
    }
    /// `argv[0]` as `%s` prints it ("(null)" for NULL).
    #[inline]
    fn prog(&self) -> &'a [u8] {
        // SAFETY: as in `bytes`.
        unsafe { name_bytes(self.v[0]) }
    }
    #[inline]
    fn swap(&mut self, a: c_int, b: c_int) {
        self.v.swap(a as usize, b as usize);
    }
}

/// The long option table: the entries before the one with a NULL name; each name a C string.
#[derive(Clone, Copy)]
struct LongOpts<'a> {
    p: *const COption,
    _t: core::marker::PhantomData<&'a [COption]>,
}

impl<'a> LongOpts<'a> {
    /// # Safety
    /// `p` is NULL or an array of `struct option` ended by an entry whose name is NULL, each name a C string, all valid
    /// and unchanged for `'a`.
    unsafe fn new(p: *const COption) -> Option<LongOpts<'a>> {
        if p.is_null() { None } else { Some(LongOpts { p, _t: core::marker::PhantomData }) }
    }
    /// Look for the entry named exactly `name`, scanning in order: `Ok((index, the entries up to it))`, or
    /// `Err(all the entries)` when there is none.
    fn exact(&self, name: &[u8]) -> Result<(usize, Table<'a>), Table<'a>> {
        let mut n = 0;
        loop {
            // SAFETY: the array is readable up to its NULL-named entry (`new`'s contract), and the loop stops there.
            let e = unsafe { &*self.p.wrapping_add(n) };
            if e.name.is_null() {
                // SAFETY: the `n` entries before the terminator are initialised and stay valid for `'a`.
                return Err(Table { o: unsafe { ffi::slice(self.p, n) } });
            }
            let t = Table { o: core::slice::from_ref(e) };
            if t.matches(0, name) == Some(true) {
                // SAFETY: as above, for the `n + 1` entries scanned.
                return Ok((n, Table { o: unsafe { ffi::slice(self.p, n + 1) } }));
            }
            n += 1;
        }
    }
}

/// Entries of the long option table before its terminator: each name a non-NULL C string valid for `'a` (only
/// `LongOpts::exact` makes one, from the entries it scanned).
#[derive(Clone, Copy)]
struct Table<'a> {
    o: &'a [COption],
}

impl<'a> Table<'a> {
    /// How entry `i`'s name compares with `name` (which has no NUL): None when it does not start with it, Some(true) when
    /// it is equal, Some(false) when it is longer.
    #[inline]
    fn matches(&self, i: usize, name: &[u8]) -> Option<bool> {
        let p = self.o[i].name;
        for (k, &c) in name.iter().enumerate() {
            // SAFETY: the name is a C string valid for `'a` (the type's invariant) and its bytes before `k` matched
            // `name`, so they are not NUL.
            if unsafe { cbyte(p, k) } != c {
                return None;
            }
        }
        // SAFETY: as above, the `name.len()` bytes before matched.
        Some(unsafe { cbyte(p, name.len()) } == 0)
    }
    #[inline]
    fn name(&self, i: usize) -> &'a [u8] {
        // SAFETY: a non-NULL C string valid for `'a` (the type's invariant).
        unsafe { ffi::cstr_bytes(self.o[i].name) }
    }
}

/// Byte `k` of the C string at `p`.
///
/// # Safety
/// `p` is a C string whose bytes before `k` are not NUL (so byte `k` is still part of it).
#[inline]
unsafe fn cbyte(p: *const c_char, k: usize) -> u8 {
    // SAFETY: forwarded contract.
    unsafe { *p.cast::<u8>().wrapping_add(k) }
}

/// Byte `i` of the C string at `p`, 0 at or past its NUL (the bytes are read in order and the scan stops at the NUL).
///
/// # Safety
/// `p` is a C string.
#[inline]
unsafe fn cstr_at(p: *const c_char, i: usize) -> u8 {
    for k in 0..i {
        // SAFETY: the bytes before `k` were not NUL, so byte `k` is part of the string.
        if unsafe { cbyte(p, k) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above, for byte `i`.
    unsafe { cbyte(p, i) }
}

/// The option string, read in place (it is scanned like glibc does, with strchr, not measured first).
#[derive(Clone, Copy)]
struct OptStr<'a> {
    p: *const c_char,
    _s: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> OptStr<'a> {
    /// # Safety
    /// `p` is a C string that stays valid and unchanged for `'a`.
    unsafe fn new(p: *const c_char) -> OptStr<'a> {
        OptStr { p, _s: core::marker::PhantomData }
    }
    /// Byte `i`, or 0 at or past the NUL.
    #[inline]
    fn at(&self, i: usize) -> u8 {
        // SAFETY: a C string valid for `'a` (`new`'s contract).
        unsafe { cstr_at(self.p, i) }
    }
    /// Without its first byte (which is not NUL).
    #[inline]
    fn skip1(self) -> OptStr<'a> {
        debug_assert!(self.at(0) != 0);
        OptStr { p: self.p.wrapping_add(1), _s: self._s }
    }
    /// `strchr(s, c) - s`: the index of the first `c`, the NUL included (`c == 0` finds the end).
    #[inline]
    fn find(&self, c: u8) -> Option<usize> {
        let mut k = 0;
        loop {
            // SAFETY: as in `at`: the bytes before `k` were not NUL.
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
    /// `strchr(s, c) != NULL` as the option string after the match (the option's specification: `:`, `::`, `;`); for
    /// `c == 0` the match is the NUL and the rest is empty. Built here, where the bytes up to the match are known not to be
    /// NUL, so byte k of the rest is byte `strchr(s, c) - s + 1 + k` without scanning the bytes before it again.
    #[inline]
    fn find_rest(&self, c: u8) -> Option<OptStr<'a>> {
        let k = self.find(c)?;
        let after = if c == 0 { k } else { k + 1 };
        Some(OptStr { p: self.p.wrapping_add(after), _s: self._s })
    }
    /// `strchr(s, c) != NULL`.
    #[inline]
    fn has(&self, c: u8) -> bool {
        self.find(c).is_some()
    }
}

/// `s[i]`, or 0 past the end (the NUL of the C string).
#[inline]
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// The bytes at `d.nextchar` up to its NUL (`d.nextchar` not NULL).
#[inline]
fn next_bytes<'a>(d: &Data) -> &'a [u8] {
    debug_assert!(!d.nextchar.is_null());
    // SAFETY: only the scanner sets `nextchar`, always to a position inside one of the argument strings (or NULL, ruled out
    // by the callers); getopt's contract is that the caller keeps passing the same vector, whose strings stay valid, until it
    // restarts with optind = 0 (which clears `nextchar` before it is read).
    unsafe { ffi::cstr_bytes(d.nextchar) }
}

/// Swap the two adjacent runs `[first_nonopt, last_nonopt)` and `[last_nonopt, optind)` of `argv`
/// (the skipped non-options and the options after them) by exchanging the shorter run with the end
/// of the longer one, repeatedly: the same element moves as glibc's, so the final order is the same.
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

/// Print a diagnostic: the translation of `msgid` run with argv[0] and `args` when the locale has one, else argv[0] and
/// the English `parts`.
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

/// A diagnostic in a locale that translates it (glibc: `fprintf(stderr, _(msgid), args...)`): printed and true; false
/// when there is no translation (the caller prints the English text).
fn say_tr(o: &mut Out, msgid: &'static CStr, args: &[u64]) -> bool {
    rusty_libc_core::i18n::tr_format(msgid, args, &mut |b: &[u8]| o.bytes(b))
}

/// The prefix as a C string for the translated formats.
fn prefix_c(prefix: &[u8]) -> u64 {
    (match prefix {
        b"--" => c"--",
        b"-W " => c"-W ",
        _ => c"-",
    })
    .as_ptr() as u64
}

/// `say` for a translated message: argv[0] first, then `args`.
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

/// What the scanner gets besides the state.
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

    // exact match first, counting the options
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
                                    // SAFETY: a fresh block of at least `n_options` bytes, owned here until freed below.
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
            // SAFETY: NULL or the block allocated above; `ambig` (its only view) is not used after this.
            unsafe { cmem::free(ambig_set) };
            d.nextchar = d.nextchar.wrapping_add(next.len());
            d.optind += 1;
            d.optopt = 0;
            return b'?' as c_int;
        }
        option_index = indfound;
    }

    let Some(pi) = pfound else {
        // not a long option: an error, unless this is getopt_long_only and it can be a short one
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
        // SAFETY: a non-NULL `flag` of a long option points to a writable int (the C contract of struct option).
        unsafe { *pf.flag = pf.val };
        return 0;
    }
    pf.val
}

/// The start of a scan: the ordering from the option string's first character or POSIXLY_CORRECT; returns the option
/// string without that character.
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

/// The safe scanner over a converted call.
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

    // SAFETY: a non-NULL `nextchar` points into one of the argument strings (see `next_bytes`), so its first byte is part
    // of that string.
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

    // the next short option character
    let argv0 = sc.argv.ptr(0);
    // SAFETY: `nextchar` is not NULL here and points into one of the argument strings (see `next_bytes`).
    let mut c = unsafe { cbyte(d.nextchar, 0) };
    // SAFETY: as above; byte 0 is not NUL, so byte 1 is still part of the string.
    let rest_empty = c == 0 || unsafe { cbyte(d.nextchar, 1) } == 0;
    d.nextchar = d.nextchar.wrapping_add(1);
    let temp = sc.optstring.find_rest(c);
    if rest_empty {
        d.optind += 1;
    }
    // `spec`: the option string after `c`
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

/// The scanner: glibc's `_getopt_internal_r`. Returns the option character (or the long option's
/// value, 0 for a flag option, 1 for a non-option in `-` mode), `'?'` for an error, `':'` for a
/// missing argument when the option string starts with `:`, and -1 at the end.
///
/// # Safety
/// `argv` must hold `argc` valid strings (and a NULL after them), `optstring` must be a C string and
/// `longopts` NULL or an array ending in an entry with a NULL name; `argv` is permuted; `longind` is NULL or writable.
/// Between calls with the same `d` the same `argv` is passed until `d.optind` is reset to 0.
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
    // SAFETY: `argv` holds `argc` pointers that only this call reaches meanwhile (caller's contract).
    let v = unsafe { ffi::slice_mut(argv, argc as usize) };
    let mut sc = Scan {
        // SAFETY: each of them is a C string valid for the call (caller's contract).
        argv: unsafe { Args::new(v) },
        // SAFETY: `optstring` is a C string (caller's contract).
        optstring: unsafe { OptStr::new(optstring) },
        // SAFETY: `longopts` is NULL or a terminated table (caller's contract).
        longopts: unsafe { LongOpts::new(longopts) },
        // SAFETY: `longind` is NULL or writable (caller's contract).
        longind: unsafe { ffi::out(longind) },
        long_only,
        print_errors: d.opterr != 0,
    };
    scan(&mut sc, d, posixly_correct)
}

/// Run the scanner on the global state (glibc's `_getopt_internal`): copy `optind` and `opterr`
/// in, the results out.
///
/// # Safety
/// As `getopt_internal_r`, and not concurrently with another getopt call (the rule of the globals).
unsafe fn internal(argc: c_int, argv: *mut *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int, long_only: bool, posixly: bool) -> c_int {
    // SAFETY: no other getopt call runs meanwhile (the rule of the globals and STATE), so this is the only access.
    let st = unsafe { &mut *STATE.as_ptr() };
    // SAFETY: as above.
    st.optind = unsafe { optind };
    // SAFETY: as above.
    st.opterr = unsafe { opterr };
    // SAFETY: forwarded contract.
    let r = unsafe { getopt_internal_r(argc, argv, optstring, longopts, longind, long_only, st, posixly) };
    // SAFETY: as above.
    unsafe { optind = st.optind };
    // SAFETY: as above.
    unsafe { optarg = st.optarg };
    // SAFETY: as above.
    unsafe { optopt = st.optopt };
    r
}

/// # Safety
/// See [`getopt_internal_r`]; `argv` is permuted despite its `const` type.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, core::ptr::null(), null_mut(), false, false) }
}

/// The POSIX variant: stops at the first non-option as if `POSIXLY_CORRECT` were set (glibc's
/// headers select it for strict POSIX programs).
///
/// # Safety
/// As `getopt`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __posix_getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, core::ptr::null(), null_mut(), false, true) }
}

/// # Safety
/// As `getopt`; `longopts` ends with an entry whose name is NULL; `longind` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long(argc: c_int, argv: *const *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, longopts, longind, false, false) }
}

/// # Safety
/// As `getopt_long`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long_only(argc: c_int, argv: *const *mut c_char, optstring: *const c_char, longopts: *const COption, longind: *mut c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { internal(argc, argv as *mut *mut c_char, optstring, longopts, longind, true, false) }
}
