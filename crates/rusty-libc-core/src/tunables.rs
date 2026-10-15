#![allow(dead_code)]

pub struct Tunables<'a> {
    pub enable_secure: bool,
    pub hwcaps: Option<&'a [u8]>,
    pub prefer_map_32bit_exec: bool,
    pub execstack: u8,
    pub nns: usize,
    pub optional_static_tls: usize,
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
    pub fn sync(&mut self) {
        let v = &self.values.0;
        self.hwcaps = v[HWCAPS].str;
        self.prefer_map_32bit_exec = v[MAP32].num == 1;
        self.execstack = v[EXECSTACK].num as u8;
        self.nns = v[NNS].num as usize;
        self.optional_static_tls = v[OPTIONAL_STATIC_TLS].num as usize;
    }
}

pub enum Warning<'a> {
    BadString,
    BadValue(&'a [u8], &'static str),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ty {
    I32,
    U64,
    Size,
    Str,
}

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
const SMAX: i64 = -1;
const I32MAX: i64 = i32::MAX as i64;

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

pub fn name(i: usize) -> &'static str {
    NAMES.get(i)
}

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

#[derive(Clone, Copy)]
pub struct Val<'a> {
    pub num: i64,
    pub str: Option<&'a [u8]>,
    pub initialized: bool,
}

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
            None => return (u64::MAX, i),
        }
        i += 1;
    }
    (if positive { r } else { r.wrapping_neg() }, i)
}

fn parse_num(v: &[u8]) -> Option<u64> {
    let (n, used) = strtoul(v);
    if used == v.len() { Some(n) } else { None }
}

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

pub fn index_of(name: &[u8]) -> Option<usize> {
    NAMES.position(name)
}

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

pub fn hwcap_feature(name: &[u8]) -> Option<(usize, usize, u32, bool)> {
    HWCAP_NAMES.position(name).map(|i| HWCAP_BITS[i])
}

pub const UNSECURE_ENVVARS: [&[u8]; 34] = [
    b"GCONV_PATH", b"GETCONF_DIR", b"GLIBC_TUNABLES", b"HOSTALIASES", b"LD_AUDIT", b"LD_BIND_NOT", b"LD_BIND_NOW", b"LD_DEBUG",
    b"LD_DEBUG_OUTPUT", b"LD_DYNAMIC_WEAK", b"LD_LIBRARY_PATH", b"LD_ORIGIN_PATH", b"LD_PRELOAD", b"LD_PROFILE", b"LD_PROFILE_OUTPUT",
    b"LD_SHOW_AUXV", b"LD_VERBOSE", b"LD_WARN", b"LOCALDOMAIN", b"LOCPATH", b"MALLOC_ARENA_MAX", b"MALLOC_ARENA_TEST",
    b"MALLOC_MMAP_MAX_", b"MALLOC_MMAP_THRESHOLD_", b"MALLOC_PERTURB_", b"MALLOC_TOP_PAD_", b"MALLOC_TRACE",
    b"MALLOC_TRIM_THRESHOLD_", b"NIS_PATH", b"NLSPATH", b"RESOLV_HOST_CONF", b"RES_OPTIONS", b"TMPDIR", b"TZDIR",
];

static UNSECURE: crate::strtab::StrTab<34, { crate::strtab::packed_len_bytes(&UNSECURE_ENVVARS) }> = crate::strtab::StrTab::from_bytes(&UNSECURE_ENVVARS);

unsafe fn cbytes<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    loop {
        let q = unsafe { p.add(n) };
        if unsafe { *q } == 0 {
            break;
        }
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}

#[inline(always)]
unsafe fn entry(envp: *const *mut u8, i: usize) -> *mut u8 {
    let e = unsafe { envp.add(i) };
    unsafe { *e }
}

pub unsafe fn scrub_unsecure_env(envp: *mut *mut u8) {
    let (mut w, mut r) = (0usize, 0usize);
    loop {
        let e = unsafe { entry(envp, r) };
        if e.is_null() {
            break;
        }
        let v = unsafe { cbytes(e) };
        let name = match v.iter().position(|&c| c == b'=') {
            Some(p) => &v[..p],
            None => v,
        };
        if UNSECURE.position(name).is_none() {
            let slot = unsafe { envp.add(w) };
            unsafe { *slot = e };
            w += 1;
        }
        r += 1;
    }
    let slot = unsafe { envp.add(w) };
    unsafe { *slot = core::ptr::null_mut() };
}

pub unsafe fn find_env<'a>(envp: *const *mut u8) -> Option<&'a [u8]> {
    const NAME: &[u8] = b"GLIBC_TUNABLES=";
    let mut k = 0;
    loop {
        let p = unsafe { entry(envp, k) };
        if p.is_null() {
            return None;
        }
        let mut i = 0;
        while i < NAME.len() {
            let q = unsafe { p.add(i) };
            if unsafe { *q } != NAME[i] {
                break;
            }
            i += 1;
        }
        if i == NAME.len() {
            let v = unsafe { p.add(i) };
            return Some(unsafe { cbytes(v) });
        }
        k += 1;
    }
}

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

pub unsafe fn apply_aliases<'a>(vals: &mut Values<'a>, envp: *const *mut u8, warn: &mut dyn FnMut(Warning<'a>)) {
    {
        let mut alias: [Option<&'a [u8]>; COUNT] = [None; COUNT];
        let mut k = 0;
        loop {
            let p = unsafe { entry(envp, k) };
            if p.is_null() {
                break;
            }
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

static NUM: [core::sync::atomic::AtomicI64; COUNT] = [const { core::sync::atomic::AtomicI64::new(0) }; COUNT];
static SET: [core::sync::atomic::AtomicBool; COUNT] = [const { core::sync::atomic::AtomicBool::new(false) }; COUNT];

pub fn store(vals: &Values<'_>) {
    use core::sync::atomic::Ordering::Relaxed;
    for (i, v) in vals.0.iter().enumerate() {
        NUM[i].store(v.num, Relaxed);
        SET[i].store(v.initialized, Relaxed);
    }
}

pub fn stored(i: usize) -> Option<i64> {
    use core::sync::atomic::Ordering::Relaxed;
    SET[i].load(Relaxed).then(|| NUM[i].load(Relaxed))
}

pub unsafe fn init_static(envp: *mut *mut u8, mut secure: bool, warn: &mut dyn FnMut(&[u8]), hwcaps: &mut dyn FnMut(&[u8])) -> bool {
    {
        let mut vals = Values::default();
        if let Some(v) = unsafe { find_env(envp) }.filter(|_| !secure) {
            let t = parse(v, &mut |w| warning_text(&w, v, warn));
            secure = t.enable_secure;
            if let Some(h) = t.hwcaps.filter(|_| !secure) {
                hwcaps(h);
            }
            vals = t.values;
        }
        if !secure {
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
            unsafe { scrub_unsecure_env(envp) };
        }
        secure
    }
}

