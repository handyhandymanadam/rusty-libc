//! `GLIBC_TUNABLES`: the parsing and ignoring rules of glibc's `__tunables_init` (elf/dl-tunables.c), written from its
//! behaviour. One file, used by the loader and by libc.so.6 / libc.a (each includes it as a module), so that both read the
//! variable the same way. (rusty-libc-core owns the file; the loader crate includes it with `#[path]`.)
//!
//! The variable is a list `name=value:name=value`. Names that are not tunables are skipped; a later value of a name replaces
//! an earlier one. A string that is not well formed (a name without `=`, a value that contains `=`, a trailing `:`) is
//! ignored as a whole. `glibc.rtld.enable_secure=1` makes the process behave as a set-user-ID one and every other tunable
//! of the variable is dropped. A number is read like glibc's `_dl_strtoul` (`0x` hexadecimal, a leading `0` octal).
//! Every glibc 2.43 tunable is parsed, bounds-checked and kept (`LIST`, `Values`; the loader hands them out through
//! `__tunable_get_val`); the loader and libc act on `glibc.rtld.enable_secure`, `glibc.cpu.hwcaps`,
//! `glibc.cpu.prefer_map_32bit_exec`, `glibc.rtld.execstack`, `glibc.rtld.nns` and `glibc.rtld.optional_static_tls`.
#![allow(dead_code)]

/// What the variable asked for.
pub struct Tunables<'a> {
    pub enable_secure: bool,
    /// `glibc.cpu.hwcaps`: the comma-separated feature list, unparsed.
    pub hwcaps: Option<&'a [u8]>,
    pub prefer_map_32bit_exec: bool,
    /// `glibc.rtld.execstack`: 0 forbids an executable stack, 1 (default) makes the stack executable when a library linked at
    /// start-up needs it, 2 makes it executable at start-up.
    pub execstack: u8,
    /// `glibc.rtld.nns`: how many dlmopen namespaces the static TLS surplus is sized for (1..=16, default 4).
    pub nns: usize,
    /// `glibc.rtld.optional_static_tls`: bytes of the static TLS surplus kept for optimisation (default 512).
    pub optional_static_tls: usize,
    /// Every tunable, for `__tunable_get_val` (the fields above are read from it).
    pub values: Values<'a>,
}

impl Default for Tunables<'_> {
    fn default() -> Self {
        Tunables {
            enable_secure: false,
            hwcaps: None,
            prefer_map_32bit_exec: false,
            execstack: 1,
            nns: 4,
            optional_static_tls: 512,
            values: Values::default(),
        }
    }
}

impl Tunables<'_> {
    /// Read the fields the loader and libc use from `values`.
    pub fn sync(&mut self) {
        let v = &self.values.0;
        self.hwcaps = v[HWCAPS].str;
        self.prefer_map_32bit_exec = v[MAP32].num == 1;
        self.execstack = v[EXECSTACK].num as u8;
        self.nns = v[NNS].num as usize;
        self.optional_static_tls = v[OPTIONAL_STATIC_TLS].num as usize;
    }
}

/// A complaint glibc prints on stderr and goes on.
pub enum Warning<'a> {
    /// `WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored.`
    BadString,
    /// `WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored.`
    BadValue(&'a [u8], &'static str),
}

/// A tunable's type (glibc's `tunable_type_code_t`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ty {
    I32,
    U64,
    Size,
    Str,
}

/// One row of glibc's `tunable_list`: name, type, bounds, default value and the old environment variable that also sets it.
pub struct Def {
    pub name: &'static str,
    pub ty: Ty,
    pub min: i64,
    pub max: i64,
    pub def: i64,
    pub alias: &'static [u8],
}

const fn d(name: &'static str, ty: Ty, min: i64, max: i64, def: i64, alias: &'static [u8]) -> Def {
    Def { name, ty, min, max, def, alias }
}
const SMAX: i64 = -1; // SIZE_MAX as glibc's tunable_num_t (int64_t)
const I32MAX: i64 = i32::MAX as i64;

/// Every tunable glibc 2.43 knows on x86-64 Linux (elf/dl-tunables.list, sysdeps/nptl, sysdeps/x86_64/64 and sysdeps/x86),
/// in the order glibc's scripts/gen-tunables.awk writes them: the index is glibc's `tunable_id_t`, which programs pass to
/// `__tunable_get_val`.
pub const LIST: [Def; 37] = [
    d("glibc.cpu.hwcaps", Ty::Str, 0, 0, 0, b""),
    d("glibc.cpu.plt_rewrite", Ty::I32, 0, 2, 0, b""),
    d("glibc.cpu.prefer_map_32bit_exec", Ty::I32, 0, 1, 0, b"LD_PREFER_MAP_32BIT_EXEC"),
    d("glibc.cpu.x86_data_cache_size", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.cpu.x86_ibt", Ty::Str, 0, 0, 0, b""),
    d("glibc.cpu.x86_memset_non_temporal_threshold", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.cpu.x86_non_temporal_threshold", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.cpu.x86_rep_movsb_threshold", Ty::Size, 1, SMAX, 0, b""),
    d("glibc.cpu.x86_rep_stosb_threshold", Ty::Size, 1, SMAX, 2048, b""),
    d("glibc.cpu.x86_shared_cache_size", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.cpu.x86_shstk", Ty::Str, 0, 0, 0, b""),
    d("glibc.gmon.maxarcs", Ty::I32, 50, I32MAX, 1048576, b""),
    d("glibc.gmon.minarcs", Ty::I32, 50, I32MAX, 50, b""),
    d("glibc.malloc.arena_max", Ty::Size, 1, SMAX, 0, b"MALLOC_ARENA_MAX"),
    d("glibc.malloc.arena_test", Ty::Size, 1, SMAX, 0, b"MALLOC_ARENA_TEST"),
    d("glibc.malloc.check", Ty::I32, 0, 3, 0, b"MALLOC_CHECK_"),
    d("glibc.malloc.hugetlb", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.malloc.mmap_max", Ty::I32, 0, I32MAX, 0, b"MALLOC_MMAP_MAX_"),
    d("glibc.malloc.mmap_threshold", Ty::Size, 0, SMAX, 0, b"MALLOC_MMAP_THRESHOLD_"),
    d("glibc.malloc.mxfast", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.malloc.perturb", Ty::I32, 0, 0xff, 0, b"MALLOC_PERTURB_"),
    d("glibc.malloc.tcache_count", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.malloc.tcache_max", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.malloc.tcache_unsorted_limit", Ty::Size, 0, SMAX, 0, b""),
    d("glibc.malloc.top_pad", Ty::Size, 0, SMAX, 131072, b"MALLOC_TOP_PAD_"),
    d("glibc.malloc.trim_threshold", Ty::Size, 0, SMAX, 0, b"MALLOC_TRIM_THRESHOLD_"),
    d("glibc.mem.decorate_maps", Ty::I32, 0, 1, 0, b""),
    d("glibc.mem.tagging", Ty::I32, 0, 255, 0, b""),
    d("glibc.pthread.mutex_spin_count", Ty::I32, 0, 32767, 100, b""),
    d("glibc.pthread.rseq", Ty::I32, 0, 1, 1, b""),
    d("glibc.pthread.stack_cache_size", Ty::Size, 0, SMAX, 41943040, b""),
    d("glibc.pthread.stack_hugetlb", Ty::I32, 0, 1, 1, b""),
    d("glibc.rtld.dynamic_sort", Ty::I32, 1, 2, 2, b""),
    d("glibc.rtld.enable_secure", Ty::I32, 0, 1, 0, b""),
    d("glibc.rtld.execstack", Ty::I32, 0, 2, 1, b""),
    d("glibc.rtld.nns", Ty::Size, 1, 16, 4, b""),
    d("glibc.rtld.optional_static_tls", Ty::Size, 0, SMAX, 512, b""),
];
pub const COUNT: usize = LIST.len();

// The run-time copies of LIST: `LIST` indexed at run time would become a table of 37 rows with two pointers each, all relocated
// by the loader at every start; the names and aliases go in pointer-free string tables (crate::strtab) instead.
const fn names(alias: bool) -> [&'static str; COUNT] {
    let mut out = [""; COUNT];
    let mut i = 0;
    while i < COUNT {
        out[i] = if alias {
            match core::str::from_utf8(LIST[i].alias) {
                Ok(s) => s,
                Err(_) => panic!("alias not UTF-8"),
            }
        } else {
            LIST[i].name
        };
        i += 1;
    }
    out
}
static NAMES: crate::strtab::StrTab<COUNT, { crate::strtab::packed_len(&names(false)) }> = crate::strtab::StrTab::new(&names(false));
static ALIASES: crate::strtab::StrTab<COUNT, { crate::strtab::packed_len(&names(true)) }> = crate::strtab::StrTab::new(&names(true));

/// The numbers of one row of LIST.
#[derive(Clone, Copy)]
pub struct Num {
    pub ty: Ty,
    pub min: i64,
    pub max: i64,
    pub def: i64,
}
static NUMS: [Num; COUNT] = {
    let mut out = [Num { ty: Ty::I32, min: 0, max: 0, def: 0 }; COUNT];
    let mut i = 0;
    while i < COUNT {
        out[i] = Num { ty: LIST[i].ty, min: LIST[i].min, max: LIST[i].max, def: LIST[i].def };
        i += 1;
    }
    out
};

/// Tunable `i`'s name (`LIST[i].name`).
pub fn name(i: usize) -> &'static str {
    NAMES.get(i)
}

/// Tunable `i`'s type, bounds and default (`LIST[i]`); `i` must be below COUNT.
pub fn num(i: usize) -> Num {
    NUMS[i]
}
pub const HWCAPS: usize = 0;
pub const MAP32: usize = 2;
pub const ENABLE_SECURE: usize = 33;
pub const EXECSTACK: usize = 34;
pub const NNS: usize = 35;
pub const OPTIONAL_STATIC_TLS: usize = 36;
pub const MALLOC_ARENA_MAX: usize = 13;
pub const MALLOC_ARENA_TEST: usize = 14;
pub const MALLOC_HUGETLB: usize = 16;
pub const MALLOC_MMAP_MAX: usize = 17;
pub const MALLOC_MMAP_THRESHOLD: usize = 18;
pub const MALLOC_PERTURB: usize = 20;
pub const MALLOC_TCACHE_COUNT: usize = 21;
pub const MALLOC_TCACHE_MAX: usize = 22;
pub const MALLOC_TOP_PAD: usize = 24;
pub const MALLOC_TRIM_THRESHOLD: usize = 25;

/// The value of one tunable after parsing (glibc's `tunable_val_t` plus its `initialized` flag).
#[derive(Clone, Copy)]
pub struct Val<'a> {
    pub num: i64,
    pub str: Option<&'a [u8]>,
    pub initialized: bool,
}

/// Every tunable's value: the defaults, then what the variable (or an alias variable) set.
#[derive(Clone, Copy)]
pub struct Values<'a>(pub [Val<'a>; COUNT]);

impl Default for Values<'_> {
    fn default() -> Self {
        let mut v = [Val { num: 0, str: None, initialized: false }; COUNT];
        for (i, x) in v.iter_mut().enumerate() {
            x.num = NUMS[i].def;
        }
        Values(v)
    }
}

impl<'a> Values<'a> {
    /// glibc's `tunable_initialize`: false when a number does not parse (the caller warns); a number outside the bounds
    /// leaves the tunable unchanged without a message (`do_tunable_update_val`).
    pub fn initialize(&mut self, i: usize, v: &'a [u8]) -> bool {
        let def = &NUMS[i];
        let cur = &mut self.0[i];
        if def.ty == Ty::Str {
            cur.str = Some(v);
            cur.initialized = true;
            return true;
        }
        let Some(n) = parse_num(v) else { return false };
        let val = match def.ty {
            Ty::I32 => n as i32 as i64,
            _ => n as i64,
        };
        let ok = if def.ty == Ty::I32 {
            val >= def.min && val <= def.max
        } else {
            (val as u64) >= (def.min as u64) && (val as u64) <= (def.max as u64)
        };
        if ok {
            cur.num = val;
            cur.initialized = true;
        }
        true
    }
}

/// `_dl_strtoul` on `s`: the value and how many bytes it used (0 when there is no number).
fn strtoul(s: &[u8]) -> (u64, usize) {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut i = 0;
    while at(i) == b' ' || at(i) == b'\t' {
        i += 1;
    }
    let mut positive = true;
    if at(i) == b'-' {
        positive = false;
        i += 1;
    } else if at(i) == b'+' {
        i += 1;
    }
    if !at(i).is_ascii_digit() {
        return (0, i);
    }
    let (mut base, mut max_digit) = (10u64, b'9');
    if at(i) == b'0' {
        if at(i + 1) == b'x' || at(i + 1) == b'X' {
            base = 16;
            i += 2;
        } else {
            base = 8;
            max_digit = b'7';
        }
    }
    let mut r: u64 = 0;
    loop {
        let c = at(i);
        let d = if c >= b'0' && c <= max_digit {
            (c - b'0') as u64
        } else if base == 16 && (b'a'..=b'f').contains(&c) {
            (c - b'a') as u64 + 10
        } else if base == 16 && (b'A'..=b'F').contains(&c) {
            (c - b'A') as u64 + 10
        } else {
            break;
        };
        match r.checked_mul(base).and_then(|x| x.checked_add(d)) {
            Some(x) => r = x,
            // glibc stops at the digit that overflows and returns UINT64_MAX without the sign, so the value is not whole
            None => return (u64::MAX, i),
        }
        i += 1;
    }
    (if positive { r } else { r.wrapping_neg() }, i)
}

/// The whole of `v` must be a number.
fn parse_num(v: &[u8]) -> Option<u64> {
    let (n, used) = strtoul(v);
    if used == v.len() { Some(n) } else { None }
}

/// glibc's `parse_tunables_string`: the (name, value) pairs in order, or None when the string is ill formed.
fn pairs<'a>(s: &'a [u8], mut f: impl FnMut(&'a [u8], &'a [u8])) -> bool {
    if s.is_empty() {
        return true;
    }
    let mut p = 0;
    loop {
        let name = p;
        while p < s.len() && s[p] != b'=' && s[p] != b':' {
            p += 1;
        }
        if p == s.len() {
            return false;
        }
        if s[p] == b':' {
            p += 1;
            continue;
        }
        let name = &s[name..p];
        p += 1;
        let value = p;
        while p < s.len() && s[p] != b'=' && s[p] != b':' {
            p += 1;
        }
        if p < s.len() && s[p] == b'=' {
            return false;
        }
        f(name, &s[value..p]);
        if p == s.len() {
            return true;
        }
    }
}

/// glibc's `tunable_is_name` for a name taken from the variable.
pub fn index_of(name: &[u8]) -> Option<usize> {
    NAMES.position(name)
}

/// Parse the value of `GLIBC_TUNABLES` (glibc's `parse_tunables`): the last value of each name wins, then the tunables are
/// set in table order, each bad number reported.
pub fn parse<'a>(s: &'a [u8], warn: &mut dyn FnMut(Warning<'a>)) -> Tunables<'a> {
    let mut t = Tunables::default();
    let mut toset: [Option<&'a [u8]>; COUNT] = [None; COUNT];
    if !pairs(s, |n, v| {
        if let Some(i) = index_of(n) {
            toset[i] = Some(v);
        }
    }) {
        warn(Warning::BadString);
        return t;
    }
    if let Some(v) = toset[ENABLE_SECURE] {
        match parse_num(v) {
            None => warn(Warning::BadValue(v, name(ENABLE_SECURE))),
            Some(1) => {
                t.enable_secure = true;
                return t;
            }
            Some(_) => {}
        }
    }
    for (i, v) in toset.iter().enumerate() {
        if let Some(v) = *v
            && !t.values.initialize(i, v)
        {
            warn(Warning::BadValue(v, name(i)));
        }
    }
    t.sync();
    t
}

/// The `glibc.cpu.hwcaps` list: `-NAME` turns a feature off, `NAME` turns one on (only the names glibc's
/// `set_hwcaps` accepts for that: off for most, either way for SHSTK). Calls `f(name, disable)` for every item.
pub fn hwcaps_items<'a>(list: &'a [u8], mut f: impl FnMut(&'a [u8], bool)) {
    for item in list.split(|&c| c == b',') {
        if item.is_empty() {
            continue;
        }
        if item[0] == b'-' {
            f(&item[1..], true);
        } else {
            f(item, false);
        }
    }
}

/// A feature `glibc.cpu.hwcaps` can switch: (name, leaf index of `__x86_get_cpuid_feature_leaf`, register
/// eax/ebx/ecx/edx = 0..3, bit, may also be switched on). Names and bits read from glibc's `<bits/platform/x86.h>`
/// (tools/gen_cpuid_masks.py); the list is the one in sysdeps/x86/cpu-tunables.c.
pub const HWCAP_FEATURES: [(&[u8], usize, usize, u32, bool); 30] = [
    (b"AVX", 0, 2, 28, false),
    (b"CX8", 0, 3, 8, false),
    (b"FMA", 0, 2, 12, false),
    (b"HTT", 0, 3, 28, false),
    (b"IBT", 1, 3, 20, false),
    (b"RTM", 1, 1, 11, false),
    (b"AVX2", 1, 1, 5, false),
    (b"BMI1", 1, 1, 3, false),
    (b"BMI2", 1, 1, 8, false),
    (b"CMOV", 0, 3, 15, false),
    (b"ERMS", 1, 1, 9, false),
    (b"FMA4", 2, 2, 16, false),
    (b"SSE2", 0, 3, 26, false),
    (b"SHSTK", 1, 2, 7, true),
    (b"LZCNT", 2, 2, 5, false),
    (b"MOVBE", 0, 2, 22, false),
    (b"SSSE3", 0, 2, 9, false),
    (b"XSAVE", 0, 2, 26, false),
    (b"POPCNT", 0, 2, 23, false),
    (b"SSE4_1", 0, 2, 19, false),
    (b"SSE4_2", 0, 2, 20, false),
    (b"XSAVEC", 3, 0, 1, false),
    (b"AVX512F", 1, 1, 16, false),
    (b"OSXSAVE", 0, 2, 27, false),
    (b"AVX512CD", 1, 1, 28, false),
    (b"AVX512BW", 1, 1, 30, false),
    (b"AVX512DQ", 1, 1, 17, false),
    (b"AVX512ER", 1, 1, 27, false),
    (b"AVX512PF", 1, 1, 26, false),
    (b"AVX512VL", 1, 1, 31, false),
];

const fn hwcap_names() -> [&'static [u8]; HWCAP_FEATURES.len()] {
    let mut out: [&[u8]; HWCAP_FEATURES.len()] = [&[]; HWCAP_FEATURES.len()];
    let mut i = 0;
    while i < out.len() {
        out[i] = HWCAP_FEATURES[i].0;
        i += 1;
    }
    out
}
// run-time copies without pointers (see NAMES)
static HWCAP_NAMES: crate::strtab::StrTab<{ HWCAP_FEATURES.len() }, { crate::strtab::packed_len_bytes(&hwcap_names()) }> =
    crate::strtab::StrTab::from_bytes(&hwcap_names());
static HWCAP_BITS: [(usize, usize, u32, bool); HWCAP_FEATURES.len()] = {
    let mut out = [(0, 0, 0, false); HWCAP_FEATURES.len()];
    let mut i = 0;
    while i < out.len() {
        let f = HWCAP_FEATURES[i];
        out[i] = (f.1, f.2, f.3, f.4);
        i += 1;
    }
    out
};

/// The row of HWCAP_FEATURES named `name`: (leaf index, register, bit, may also be switched on).
pub fn hwcap_feature(name: &[u8]) -> Option<(usize, usize, u32, bool)> {
    HWCAP_NAMES.position(name).map(|i| HWCAP_BITS[i])
}

/// The variables a set-user-ID or set-group-ID program must not see (glibc's UNSECURE_ENVVARS): they could redirect library
/// loading, locale and message files, name resolution or malloc tracing.
pub const UNSECURE_ENVVARS: [&[u8]; 34] = [
    b"GCONV_PATH", b"GETCONF_DIR", b"GLIBC_TUNABLES", b"HOSTALIASES", b"LD_AUDIT", b"LD_BIND_NOT", b"LD_BIND_NOW", b"LD_DEBUG",
    b"LD_DEBUG_OUTPUT", b"LD_DYNAMIC_WEAK", b"LD_LIBRARY_PATH", b"LD_ORIGIN_PATH", b"LD_PRELOAD", b"LD_PROFILE", b"LD_PROFILE_OUTPUT",
    b"LD_SHOW_AUXV", b"LD_VERBOSE", b"LD_WARN", b"LOCALDOMAIN", b"LOCPATH", b"MALLOC_ARENA_MAX", b"MALLOC_ARENA_TEST",
    b"MALLOC_MMAP_MAX_", b"MALLOC_MMAP_THRESHOLD_", b"MALLOC_PERTURB_", b"MALLOC_TOP_PAD_", b"MALLOC_TRACE",
    b"MALLOC_TRIM_THRESHOLD_", b"NIS_PATH", b"NLSPATH", b"RESOLV_HOST_CONF", b"RES_OPTIONS", b"TMPDIR", b"TZDIR",
];

// run-time copy without pointers (see NAMES)
static UNSECURE: crate::strtab::StrTab<34, { crate::strtab::packed_len_bytes(&UNSECURE_ENVVARS) }> = crate::strtab::StrTab::from_bytes(&UNSECURE_ENVVARS);

// A private byte loop, not `ffi::cstr_bytes_scalar`: this file is also compiled into ld.so (rusty-libc-ldso includes it by
// path and does not depend on core), and it runs before the IFUNC resolvers (so no dispatched strlen either).
///
/// # Safety
/// `p` is a NUL-terminated string that stays valid and unchanged for `'a`.
unsafe fn cbytes<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    loop {
        // SAFETY: bytes 0..n are not NUL, so byte n is still part of the string (at worst its NUL).
        let q = unsafe { p.add(n) };
        // SAFETY: as above.
        if unsafe { *q } == 0 {
            break;
        }
        n += 1;
    }
    // SAFETY: the `n` bytes before the NUL, valid for `'a` (caller's contract).
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// Entry `i` of the NULL-terminated array `envp`.
///
/// # Safety
/// Entries `0..=i` exist (none of `0..i` was NULL).
#[inline(always)]
unsafe fn entry(envp: *const *mut u8, i: usize) -> *mut u8 {
    // SAFETY: caller's contract.
    let e = unsafe { envp.add(i) };
    // SAFETY: as above.
    unsafe { *e }
}

/// Remove the entries of `UNSECURE_ENVVARS` from the environment array in place (the strings stay where they are).
///
/// # Safety
/// `envp` is a NULL-terminated array of C strings that may be written.
pub unsafe fn scrub_unsecure_env(envp: *mut *mut u8) {
    // `w` never passes `r`: entries are only moved down
    let (mut w, mut r) = (0usize, 0usize);
    loop {
        // SAFETY: entries up to the NULL exist (caller's contract); the walk stops at it.
        let e = unsafe { entry(envp, r) };
        if e.is_null() {
            break;
        }
        // SAFETY: an environment string (caller's contract).
        let v = unsafe { cbytes(e) };
        let name = match v.iter().position(|&c| c == b'=') {
            Some(p) => &v[..p],
            None => v,
        };
        if UNSECURE.position(name).is_none() {
            // SAFETY: `w <= r`, an entry of the writable array (caller's contract).
            let slot = unsafe { envp.add(w) };
            // SAFETY: as above.
            unsafe { *slot = e };
            w += 1;
        }
        r += 1;
    }
    // SAFETY: `w <= r`, the entry that held the NULL or an earlier one.
    let slot = unsafe { envp.add(w) };
    // SAFETY: as above.
    unsafe { *slot = core::ptr::null_mut() };
}

/// The value of `GLIBC_TUNABLES` in the environment array (glibc's `get_next_env` skips entries without `=`).
///
/// # Safety
/// `envp` is a NULL-terminated array of C strings.
pub unsafe fn find_env<'a>(envp: *const *mut u8) -> Option<&'a [u8]> {
    const NAME: &[u8] = b"GLIBC_TUNABLES=";
    let mut k = 0;
    loop {
        // SAFETY: entries up to the NULL exist (caller's contract); the walk stops at it.
        let p = unsafe { entry(envp, k) };
        if p.is_null() {
            return None;
        }
        // compare byte by byte and stop at the first difference: most entries differ in the first one
        let mut i = 0;
        while i < NAME.len() {
            // SAFETY: bytes 0..i matched NAME (no NUL), so byte i is still part of the string.
            let q = unsafe { p.add(i) };
            // SAFETY: as above.
            if unsafe { *q } != NAME[i] {
                break;
            }
            i += 1;
        }
        if i == NAME.len() {
            // SAFETY: the value starts after the matched name, inside the same NUL-terminated string.
            let v = unsafe { p.add(i) };
            // SAFETY: as above; the strings live as long as the caller says (`'a`).
            return Some(unsafe { cbytes(v) });
        }
        k += 1;
    }
}

/// The text of a warning, in pieces handed to `out` (glibc's wording; `whole` is the complete variable value).
pub fn warning_text(w: &Warning<'_>, whole: &[u8], out: &mut dyn FnMut(&[u8])) {
    match w {
        Warning::BadString => {
            out(b"WARNING: ld.so: invalid GLIBC_TUNABLES `");
            out(whole);
            out(b"': ignored.\n");
        }
        Warning::BadValue(v, name) => {
            out(b"WARNING: ld.so: invalid GLIBC_TUNABLES value `");
            out(v);
            out(b"' for option `");
            out(name.as_bytes());
            out(b"': ignored.\n");
        }
    }
}

/// The old variables that also set a tunable (`MALLOC_CHECK_`, `MALLOC_TOP_PAD_`, ...; glibc's `env_alias`), after
/// `GLIBC_TUNABLES` was read (glibc's `__tunables_init`): the last entry of each name counts, and it sets the tunable only
/// where `GLIBC_TUNABLES` did not; a value that is not a number is reported as for `GLIBC_TUNABLES` (`whole` is that value).
/// The caller leaves this out in a secure run.
///
/// # Safety
/// `envp` is a NULL-terminated array of C strings that live as long as the values are used.
pub unsafe fn apply_aliases<'a>(vals: &mut Values<'a>, envp: *const *mut u8, warn: &mut dyn FnMut(Warning<'a>)) {
    {
        let mut alias: [Option<&'a [u8]>; COUNT] = [None; COUNT];
        let mut k = 0;
        loop {
            // SAFETY: entries up to the NULL exist (caller's contract); the walk stops at it.
            let p = unsafe { entry(envp, k) };
            if p.is_null() {
                break;
            }
            // SAFETY: an environment string, live for `'a` (caller's contract).
            let v: &'a [u8] = unsafe { cbytes(p) };
            if let Some(eq) = v.iter().position(|&c| c == b'=')
                && let Some(i) = (0..COUNT).find(|&i| !ALIASES.bytes(i).is_empty() && ALIASES.bytes(i) == &v[..eq])
            {
                alias[i] = Some(&v[eq + 1..]);
            }
            k += 1;
        }
        for (i, a) in alias.iter().enumerate() {
            if let Some(v) = *a
                && !vals.0[i].initialized
                && !vals.initialize(i, v)
            {
                warn(Warning::BadValue(v, name(i)));
            }
        }
    }
}

/// The numeric tunables as libc's own start-up of a static program read them (`store`), for the parts of libc that act on
/// them later (the allocator, at its first use, as glibc's `ptmalloc_init`).
static NUM: [core::sync::atomic::AtomicI64; COUNT] = [const { core::sync::atomic::AtomicI64::new(0) }; COUNT];
static SET: [core::sync::atomic::AtomicBool; COUNT] = [const { core::sync::atomic::AtomicBool::new(false) }; COUNT];

/// Keep the values the start-up of a static program read.
pub fn store(vals: &Values<'_>) {
    use core::sync::atomic::Ordering::Relaxed;
    for (i, v) in vals.0.iter().enumerate() {
        NUM[i].store(v.num, Relaxed);
        SET[i].store(v.initialized, Relaxed);
    }
}

/// Tunable `i` as the start-up of a static program stored it, when the environment set it (libc's `tunable_set` reads it).
pub fn stored(i: usize) -> Option<i64> {
    use core::sync::atomic::Ordering::Relaxed;
    SET[i].load(Relaxed).then(|| NUM[i].load(Relaxed))
}

/// Start-up of a statically linked program (a dynamic one gets this from the loader): read the variable and the old
/// variables that set tunables (kept for `stored`), let `glibc.rtld.enable_secure=1` make the program secure, and take the
/// unsecure variables out of the environment of a secure one (kernel-flagged or by the tunable). A secure program ignores
/// both. Returns whether the program is secure.
///
/// # Safety
/// `envp` is the program's environment array.
pub unsafe fn init_static(envp: *mut *mut u8, mut secure: bool, warn: &mut dyn FnMut(&[u8]), hwcaps: &mut dyn FnMut(&[u8])) -> bool {
    {
        let mut vals = Values::default();
        // SAFETY: the program's environment array (caller's contract).
        if let Some(v) = unsafe { find_env(envp) }.filter(|_| !secure) {
            let t = parse(v, &mut |w| warning_text(&w, v, warn));
            secure = t.enable_secure;
            if let Some(h) = t.hwcaps.filter(|_| !secure) {
                hwcaps(h);
            }
            vals = t.values;
        }
        if !secure {
            // SAFETY: as above; its strings live for the whole process.
            unsafe {
                apply_aliases(&mut vals, envp, &mut |w| {
                    if let Warning::BadValue(v, _) = w {
                        warning_text(&w, v, warn)
                    }
                })
            };
            store(&vals);
        }
        if secure {
            // SAFETY: as above; start-up may edit it in place (one thread).
            unsafe { scrub_unsecure_env(envp) };
        }
        secure
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    fn run(s: &[u8]) -> (Tunables<'_>, usize) {
        let mut w = 0;
        let t = parse(s, &mut |_| w += 1);
        (t, w)
    }

    #[test]
    fn well_formed() {
        let (t, w) = run(b"glibc.cpu.hwcaps=-AVX2,-AVX:glibc.cpu.prefer_map_32bit_exec=1:glibc.malloc.check=3");
        assert_eq!(w, 0);
        assert_eq!(t.hwcaps, Some(&b"-AVX2,-AVX"[..]));
        assert!(t.prefer_map_32bit_exec && !t.enable_secure);
    }

    #[test]
    fn execstack_values() {
        assert_eq!(run(b"").0.execstack, 1);
        assert_eq!(run(b"glibc.rtld.execstack=0").0.execstack, 0);
        assert_eq!(run(b"glibc.rtld.execstack=2").0.execstack, 2);
        assert_eq!(run(b"glibc.rtld.execstack=0:glibc.rtld.execstack=2").0.execstack, 2);
        // out of range: ignored without a message (the default stays); not a number: a message
        for s in [&b"glibc.rtld.execstack=3"[..], b"glibc.rtld.execstack=-1", b"glibc.rtld.execstack=0x100000001"] {
            let (t, w) = run(s);
            assert_eq!((t.execstack, w), (1, 0), "{:?}", core::str::from_utf8(s));
        }
        assert_eq!(run(b"glibc.rtld.execstack=x").1, 1);
        assert_eq!(run(b"glibc.rtld.enable_secure=1:glibc.rtld.execstack=2").0.execstack, 1);
    }

    #[test]
    fn static_tls_tunables() {
        let (t, w) = run(b"");
        assert_eq!((t.nns, t.optional_static_tls, w), (4, 512, 0));
        let (t, w) = run(b"glibc.rtld.nns=8:glibc.rtld.optional_static_tls=0x100");
        assert_eq!((t.nns, t.optional_static_tls, w), (8, 256, 0));
        // out of range (0 and 17 for nns): the default stays, no message; not a number: a message
        for s in [&b"glibc.rtld.nns=0"[..], b"glibc.rtld.nns=17", b"glibc.rtld.nns=-1"] {
            let (t, w) = run(s);
            assert_eq!((t.nns, w), (4, 0), "{:?}", core::str::from_utf8(s));
        }
        assert_eq!(run(b"glibc.rtld.nns=16").0.nns, 16);
        assert_eq!(run(b"glibc.rtld.nns=1").0.nns, 1);
        assert_eq!(run(b"glibc.rtld.nns=x").1, 1);
        assert_eq!(run(b"glibc.rtld.optional_static_tls=y").1, 1);
        assert_eq!(run(b"glibc.rtld.enable_secure=1:glibc.rtld.nns=8").0.nns, 4);
    }

    #[test]
    fn ill_formed_is_ignored_whole() {
        for s in [&b"glibc.cpu.hwcaps"[..], b"glibc.cpu.hwcaps=a=b", b"glibc.cpu.hwcaps=-AVX:", b"x"] {
            let (t, w) = run(s);
            assert_eq!(w, 1, "{:?}", core::str::from_utf8(s));
            assert!(t.hwcaps.is_none());
        }
        assert_eq!(run(b"").1, 0);
        assert_eq!(run(b":::").1, 1); // glibc: a string of colons runs off the end
    }

    #[test]
    fn enable_secure_drops_the_rest() {
        let (t, w) = run(b"glibc.cpu.hwcaps=-AVX:glibc.rtld.enable_secure=1");
        assert!(t.enable_secure && t.hwcaps.is_none() && w == 0);
        let (t, w) = run(b"glibc.rtld.enable_secure=0:glibc.cpu.hwcaps=-AVX");
        assert!(!t.enable_secure && t.hwcaps.is_some() && w == 0);
        let (t, w) = run(b"glibc.rtld.enable_secure=x:glibc.cpu.hwcaps=-AVX");
        assert!(!t.enable_secure && t.hwcaps.is_some() && w == 2); // glibc says it twice
        let (t, _) = run(b"glibc.rtld.enable_secure=0x1");
        assert!(t.enable_secure);
    }

    #[test]
    fn numbers_like_dl_strtoul() {
        assert_eq!(parse_num(b"010"), Some(8));
        assert_eq!(parse_num(b"0x1F"), Some(31));
        assert_eq!(parse_num(b" 5"), Some(5));
        assert_eq!(parse_num(b"5x"), None);
        assert_eq!(parse_num(b""), Some(0));
        assert_eq!(parse_num(b"-1"), Some(u64::MAX));
        assert_eq!(parse_num(b"99999999999999999999"), None);
        assert_eq!(strtoul(b"18446744073709551616"), (u64::MAX, 19));
        assert_eq!(parse_num(b"18446744073709551615"), Some(u64::MAX));
    }

    #[test]
    fn malloc_indexes() {
        for (i, n) in [
            (MALLOC_ARENA_MAX, "arena_max"),
            (MALLOC_ARENA_TEST, "arena_test"),
            (MALLOC_HUGETLB, "hugetlb"),
            (MALLOC_MMAP_MAX, "mmap_max"),
            (MALLOC_MMAP_THRESHOLD, "mmap_threshold"),
            (MALLOC_PERTURB, "perturb"),
            (MALLOC_TCACHE_COUNT, "tcache_count"),
            (MALLOC_TCACHE_MAX, "tcache_max"),
            (MALLOC_TOP_PAD, "top_pad"),
            (MALLOC_TRIM_THRESHOLD, "trim_threshold"),
        ] {
            assert_eq!(LIST[i].name.strip_prefix("glibc.malloc."), Some(n));
        }
    }

    #[test]
    fn aliases_after_the_variable() {
        // (name=value strings with a NULL end, as the environment block)
        fn env(list: &[&str]) -> (Vec<Vec<u8>>, Vec<*mut u8>) {
            let mut v: Vec<Vec<u8>> = list.iter().map(|s| format!("{s}\0").into_bytes()).collect();
            let p = v.iter_mut().map(|s| s.as_mut_ptr()).chain(core::iter::once(core::ptr::null_mut())).collect();
            (v, p)
        }
        let run = |tun: &'static [u8], list: &[&str]| {
            let (_keep, p) = env(list);
            let mut t = parse(tun, &mut |_| {});
            let mut warned = 0;
            unsafe { apply_aliases(&mut t.values, p.as_ptr(), &mut |_| warned += 1) };
            (t.values.0[MALLOC_MMAP_THRESHOLD].num, t.values.0[MALLOC_MMAP_THRESHOLD].initialized, t.values.0[MALLOC_TOP_PAD].num, warned)
        };
        assert_eq!(run(b"", &["MALLOC_MMAP_THRESHOLD_=4096"]), (4096, true, 131072, 0));
        assert_eq!(run(b"glibc.malloc.mmap_threshold=65536", &["MALLOC_MMAP_THRESHOLD_=4096"]), (65536, true, 131072, 0));
        assert_eq!(run(b"glibc.malloc.mmap_threshold=12k", &["MALLOC_MMAP_THRESHOLD_=4096"]), (4096, true, 131072, 0));
        assert_eq!(run(b"", &["MALLOC_MMAP_THRESHOLD_=1x"]), (0, false, 131072, 1));
        assert_eq!(run(b"", &["MALLOC_TOP_PAD_=", "MALLOC_MMAP_THRESHOLD_=1", "MALLOC_MMAP_THRESHOLD_=2"]), (2, true, 0, 0));
        assert_eq!(run(b"", &["MALLOC_MMAP_THRESHOLD", "XMALLOC_MMAP_THRESHOLD_=5"]), (0, false, 131072, 0));
    }

    #[test]
    fn every_tunable_like_tst_tunables() {
        const CHECK: usize = 15;
        const MMAP: usize = 18;
        const PERTURB: usize = 20;
        assert_eq!(LIST[CHECK].name, "glibc.malloc.check");
        assert_eq!(LIST[MMAP].name, "glibc.malloc.mmap_threshold");
        assert_eq!(LIST[PERTURB].name, "glibc.malloc.perturb");
        let get = |s: &'static [u8]| {
            let t = parse(s, &mut |_| {});
            let v = t.values.0;
            (v[CHECK].num, v[MMAP].num as u64, v[PERTURB].num)
        };
        assert_eq!(get(b"glibc.malloc.check=2"), (2, 0, 0));
        assert_eq!(get(b"glibc.malloc.check=2:glibc.malloc.mmap_threshold=4096"), (2, 4096, 0));
        assert_eq!(get(b"glibc.malloc.mmap_threshold=-1"), (0, u64::MAX, 0));
        assert_eq!(get(b"glibc.malloc.check=2::glibc.malloc.mmap_threshold=4096"), (2, 4096, 0));
        assert_eq!(get(b"glibc.malloc.check=:glibc.malloc.mmap_threshold=4096"), (0, 4096, 0));
        assert_eq!(get(b"glibc.malloc.check=2:glibc.malloc.mmap_threshold=4096:glibc.malloc.check=1"), (1, 4096, 0));
        assert_eq!(get(b"glibc.malloc.perturb=0x800"), (0, 0, 0));
        assert_eq!(get(b"glibc.malloc.perturb=0x55"), (0, 0, 0x55));
        assert_eq!(get(b":glibc.malloc.garbage=2:glibc.malloc.check=1"), (1, 0, 0));
        assert_eq!(get(b"glibc.not_valid.check=2:glibc.malloc.mmap_threshold=4096"), (0, 4096, 0));
        assert_eq!(get(b"glibc.malloc.check=2=2"), (0, 0, 0));
        assert_eq!(get(b"glibc.rtld.enable_secure=1:glibc.malloc.check=2"), (0, 0, 0));
        // a bad number is reported for any tunable, not only the ones the loader uses
        assert_eq!(run(b"glibc.malloc.check=x").1, 1);
        assert_eq!(LIST.iter().filter(|d| !d.alias.is_empty()).count(), 9);
    }
}
