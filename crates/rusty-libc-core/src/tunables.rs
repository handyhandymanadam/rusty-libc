#![allow(dead_code)]

pub struct Tunables<'a> {
    pub enable_secure: bool,
    pub hwcaps: Option<&'a [u8]>,
    pub prefer_map_32bit_exec: bool,
    pub execstack: u8,
}

impl Default for Tunables<'_> {
    fn default() -> Self {
        Tunables { enable_secure: false, hwcaps: None, prefer_map_32bit_exec: false, execstack: 1 }
    }
}

pub enum Warning<'a> {
    BadString,
    BadValue(&'a [u8], &'static str),
}

const ENABLE_SECURE: &[u8] = b"glibc.rtld.enable_secure";
const HWCAPS: &[u8] = b"glibc.cpu.hwcaps";
const MAP32: &[u8] = b"glibc.cpu.prefer_map_32bit_exec";
const EXECSTACK: &[u8] = b"glibc.rtld.execstack";

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
    let mut overflow = false;
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
            None => overflow = true,
        }
        i += 1;
    }
    if overflow {
        r = u64::MAX;
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

pub fn parse<'a>(s: &'a [u8], warn: &mut dyn FnMut(Warning<'a>)) -> Tunables<'a> {
    let mut t = Tunables::default();
    let (mut secure, mut hw, mut map32, mut execstack) = (None, None, None, None);
    if !pairs(s, |n, v| {
        if n == ENABLE_SECURE {
            secure = Some(v);
        } else if n == HWCAPS {
            hw = Some(v);
        } else if n == MAP32 {
            map32 = Some(v);
        } else if n == EXECSTACK {
            execstack = Some(v);
        }
    }) {
        warn(Warning::BadString);
        return t;
    }
    if let Some(v) = secure {
        match parse_num(v) {
            None => warn(Warning::BadValue(v, "glibc.rtld.enable_secure")),
            Some(1) => {
                t.enable_secure = true;
                return t;
            }
            Some(_) => {}
        }
    }
    if let Some(v) = map32 {
        match parse_num(v) {
            None => warn(Warning::BadValue(v, "glibc.cpu.prefer_map_32bit_exec")),
            Some(n) => t.prefer_map_32bit_exec = n == 1,
        }
    }
    if let Some(v) = execstack {
        match parse_num(v) {
            None => warn(Warning::BadValue(v, "glibc.rtld.execstack")),
            Some(n) => {
                let n = n as i32;
                if (0..=2).contains(&n) {
                    t.execstack = n as u8;
                }
            }
        }
    }
    if let Some(v) = secure.filter(|v| parse_num(v).is_none()) {
        warn(Warning::BadValue(v, "glibc.rtld.enable_secure"));
    }
    t.hwcaps = hw;
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

pub const HWCAP_FEATURES: &[(&[u8], usize, usize, u32, bool)] = &[
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

pub const UNSECURE_ENVVARS: &[&[u8]] = &[
    b"GCONV_PATH", b"GETCONF_DIR", b"GLIBC_TUNABLES", b"HOSTALIASES", b"LD_AUDIT", b"LD_BIND_NOT", b"LD_BIND_NOW", b"LD_DEBUG",
    b"LD_DEBUG_OUTPUT", b"LD_DYNAMIC_WEAK", b"LD_LIBRARY_PATH", b"LD_ORIGIN_PATH", b"LD_PRELOAD", b"LD_PROFILE", b"LD_PROFILE_OUTPUT",
    b"LD_SHOW_AUXV", b"LD_VERBOSE", b"LD_WARN", b"LOCALDOMAIN", b"LOCPATH", b"MALLOC_ARENA_MAX", b"MALLOC_ARENA_TEST",
    b"MALLOC_MMAP_MAX_", b"MALLOC_MMAP_THRESHOLD_", b"MALLOC_PERTURB_", b"MALLOC_TOP_PAD_", b"MALLOC_TRACE",
    b"MALLOC_TRIM_THRESHOLD_", b"NIS_PATH", b"NLSPATH", b"RESOLV_HOST_CONF", b"RES_OPTIONS", b"TMPDIR", b"TZDIR",
];

unsafe fn cbytes<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

pub unsafe fn scrub_unsecure_env(envp: *mut *mut u8) {
    unsafe {
        let mut w = envp;
        let mut r = envp;
        while !(*r).is_null() {
            let v = cbytes(*r);
            let name = match v.iter().position(|&c| c == b'=') {
                Some(p) => &v[..p],
                None => v,
            };
            if !UNSECURE_ENVVARS.contains(&name) {
                *w = *r;
                w = w.add(1);
            }
            r = r.add(1);
        }
        *w = core::ptr::null_mut();
    }
}

pub unsafe fn find_env<'a>(envp: *const *mut u8) -> Option<&'a [u8]> {
    unsafe {
        const NAME: &[u8] = b"GLIBC_TUNABLES=";
        let mut e = envp;
        while !(*e).is_null() {
            let p = *e;
            let mut i = 0;
            while i < NAME.len() && *p.add(i) == NAME[i] {
                i += 1;
            }
            if i == NAME.len() {
                return Some(cbytes(p.add(i)));
            }
            e = e.add(1);
        }
        None
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

pub unsafe fn init_static(envp: *mut *mut u8, mut secure: bool, warn: &mut dyn FnMut(&[u8])) {
    unsafe {
        if let Some(v) = find_env(envp).filter(|_| !secure) {
            let t = parse(v, &mut |w| warning_text(&w, v, warn));
            secure = t.enable_secure;
        }
        if secure {
            scrub_unsecure_env(envp);
        }
    }
}

