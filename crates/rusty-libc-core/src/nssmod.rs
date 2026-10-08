#![cfg_attr(not(feature = "shared"), allow(dead_code, unused_imports))]
use crate::lock::RawMutex;
use core::ffi::{c_char, c_int, c_void};

#[cfg(feature = "shared")]
unsafe extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

pub const NSS_TRYAGAIN: i32 = -2;
pub const NSS_UNAVAIL: i32 = -1;
pub const NSS_NOTFOUND: i32 = 0;
pub const NSS_SUCCESS: i32 = 1;

pub const ACT_RETURN: u8 = 0;
pub const ACT_CONTINUE: u8 = 1;
pub const ACT_MERGE: u8 = 2;

pub const MAX_SOURCES: usize = 8;
pub const NAME_MAX: usize = 24;

pub const NSS_RETURN: i32 = 2;

#[derive(Clone, Copy)]
pub struct Source {
    pub name: [u8; NAME_MAX],
    pub len: u8,
    pub act: [u8; 5],
}

impl Source {
    pub const EMPTY: Source = Source { name: [0; NAME_MAX], len: 0, act: [ACT_CONTINUE, ACT_CONTINUE, ACT_CONTINUE, ACT_RETURN, ACT_RETURN] };
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len as usize]
    }
    pub fn is(&self, n: &[u8]) -> bool {
        self.name().eq_ignore_ascii_case(n)
    }
    pub fn is_builtin(&self) -> bool {
        self.is(b"files") || self.is(b"compat") || self.is(b"dns")
    }
    pub fn action(&self, status: i32) -> u8 {
        self.act[(status + 2).clamp(0, 4) as usize]
    }
}

#[derive(Clone, Copy)]
pub struct Order {
    pub n: usize,
    pub e: [Source; MAX_SOURCES],
}

impl Order {
    pub const EMPTY: Order = Order { n: 0, e: [Source::EMPTY; MAX_SOURCES] };
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

pub fn parse_sources(spec: &[u8]) -> Option<Order> {
    let mut o = Order::EMPTY;
    let n = spec.len();
    let mut i = 0usize;
    loop {
        while i < n && is_space(spec[i]) {
            i += 1;
        }
        if i >= n {
            return Some(o);
        }
        let st = i;
        while i < n && !is_space(spec[i]) && spec[i] != b'[' {
            i += 1;
        }
        if st == i {
            return Some(o);
        }
        let word = &spec[st..i];
        let mut src = Source::EMPTY;
        if word.len() <= NAME_MAX {
            src.name[..word.len()].copy_from_slice(word);
            src.len = word.len() as u8;
        }
        while i < n && is_space(spec[i]) {
            i += 1;
        }
        if i < n && spec[i] == b'[' {
            i += 1;
            while i < n && is_space(spec[i]) {
                i += 1;
            }
            loop {
                let neg = i < n && spec[i] == b'!';
                if neg {
                    i += 1;
                }
                let ns = i;
                while i < n && !is_space(spec[i]) && spec[i] != b'=' && spec[i] != b']' {
                    i += 1;
                }
                let name = &spec[ns..i];
                let status = if name.eq_ignore_ascii_case(b"SUCCESS") {
                    NSS_SUCCESS
                } else if name.eq_ignore_ascii_case(b"UNAVAIL") {
                    NSS_UNAVAIL
                } else if name.eq_ignore_ascii_case(b"NOTFOUND") {
                    NSS_NOTFOUND
                } else if name.eq_ignore_ascii_case(b"TRYAGAIN") {
                    NSS_TRYAGAIN
                } else {
                    return None;
                };
                while i < n && is_space(spec[i]) {
                    i += 1;
                }
                if i >= n || spec[i] != b'=' {
                    return None;
                }
                i += 1;
                while i < n && is_space(spec[i]) {
                    i += 1;
                }
                let a_s = i;
                while i < n && !is_space(spec[i]) && spec[i] != b'=' && spec[i] != b']' {
                    i += 1;
                }
                let aname = &spec[a_s..i];
                let act = if aname.eq_ignore_ascii_case(b"RETURN") {
                    ACT_RETURN
                } else if aname.eq_ignore_ascii_case(b"CONTINUE") {
                    ACT_CONTINUE
                } else if aname.eq_ignore_ascii_case(b"MERGE") {
                    ACT_MERGE
                } else {
                    return None;
                };
                let slot = (status + 2) as usize;
                if neg {
                    let save = src.act[slot];
                    src.act = [act; 5];
                    src.act[slot] = save;
                } else {
                    src.act[slot] = act;
                }
                while i < n && is_space(spec[i]) {
                    i += 1;
                }
                if i < n && spec[i] == b']' {
                    break;
                }
            }
            i += 1;
        }
        if o.n < MAX_SOURCES {
            o.e[o.n] = src;
            o.n += 1;
        }
    }
}

fn default_spec(db: &[u8]) -> &'static [u8] {
    match db {
        b"hosts" | b"networks" => b"files dns",
        b"initgroups" => b"",
        b"group_compat" | b"passwd_compat" | b"shadow_compat" => b"nis",
        b"publickey" => b"nis nisplus",
        _ => b"files",
    }
}

const KNOWN_DBS: [&[u8]; 17] = [
    b"aliases", b"ethers", b"group", b"group_compat", b"gshadow", b"hosts", b"initgroups", b"netgroup", b"networks", b"passwd", b"passwd_compat", b"protocols", b"publickey", b"rpc", b"services", b"shadow", b"shadow_compat",
];

fn follows(db: &[u8]) -> Option<&'static [u8]> {
    match db {
        b"shadow" => Some(b"passwd"),
        b"gshadow" => Some(b"group"),
        b"shadow_compat" => Some(b"passwd_compat"),
        _ => None,
    }
}

static CONF_PATH: LockedPath = LockedPath::new();

struct LockedPath {
    lock: RawMutex,
    buf: core::cell::UnsafeCell<[u8; 200]>,
}
unsafe impl Sync for LockedPath {}
impl LockedPath {
    const fn new() -> LockedPath {
        LockedPath { lock: RawMutex::new(), buf: core::cell::UnsafeCell::new([0; 200]) }
    }
}

pub fn set_conf_path(path: &[u8]) {
    CONF_PATH.lock.lock_always();
    let b = unsafe { &mut *CONF_PATH.buf.get() };
    let n = path.len().min(199);
    b[..n].copy_from_slice(&path[..n]);
    b[n] = 0;
    CONF_PATH.lock.unlock_always();
}

fn conf_path(out: &mut [u8; 200]) {
    CONF_PATH.lock.lock_always();
    let b = unsafe { &*CONF_PATH.buf.get() };
    if b[0] == 0 {
        let d = b"/etc/nsswitch.conf\0";
        out[..d.len()].copy_from_slice(d);
    } else {
        *out = *b;
    }
    CONF_PATH.lock.unlock_always();
}

const CACHE_DBS: usize = 8;

struct Cached {
    db: [u8; 12],
    dlen: u8,
    sig: [u64; 3],
    order: Order,
    valid: bool,
}

struct Cache {
    lock: RawMutex,
    e: core::cell::UnsafeCell<[Cached; CACHE_DBS]>,
}
unsafe impl Sync for Cache {}

static CACHE: Cache = Cache {
    lock: RawMutex::new(),
    e: core::cell::UnsafeCell::new([const { Cached { db: [0; 12], dlen: 0, sig: [0; 3], order: Order::EMPTY, valid: false } }; CACHE_DBS]),
};

fn file_sig(path: &[u8; 200]) -> [u64; 3] {
    let mut st = [0u64; 18];
    let r = unsafe { crate::syscall::syscall2(crate::syscall::SYS_STAT, path.as_ptr() as usize, st.as_mut_ptr() as usize) };
    if let Err(e) = crate::syscall::check(r) {
        crate::errno::set(e.0);
        return [u64::MAX; 3];
    }
    [st[1], st[11] ^ (st[6] << 32), st[12]]
}

fn read_conf(path: &[u8; 200], db: &[u8]) -> Order {
    let default = || parse_sources(default_spec(db)).unwrap_or(Order::EMPTY);
    let Ok(fd) = (unsafe { crate::unistd::open(path.as_ptr() as *const c_char, 0o2000000, 0) }) else { return default() };
    let mut buf = [0u8; 32768];
    let mut len = 0usize;
    loop {
        match crate::unistd::read(fd, &mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len == buf.len() {
                    break;
                }
            }
            Err(e) if e.0 == 4 => continue,
            Err(_) => break,
        }
    }
    let _ = crate::unistd::close(fd);
    let fb = follows(db);
    let (mut own, mut fallback): (Option<Order>, Option<Order>) = (None, None);
    for line in buf[..len].split(|&c| c == b'\n') {
        let mut s = 0;
        while s < line.len() && is_space(line[s]) {
            s += 1;
        }
        let line = &line[s..];
        let mut e = 0;
        while e < line.len() && !is_space(line[e]) && line[e] != b':' {
            e += 1;
        }
        if e == 0 || e == line.len() {
            continue;
        }
        let name = &line[..e];
        let mut r = e;
        while r < line.len() && (is_space(line[r]) || line[r] == b':') {
            r += 1;
        }
        if !KNOWN_DBS.contains(&name) {
            continue;
        }
        let Some(o) = parse_sources(&line[r..]) else { return Order::EMPTY };
        if name == db {
            own = Some(o);
        } else if Some(name) == fb {
            fallback = Some(o);
        }
    }
    own.or(fallback).unwrap_or_else(default)
}

pub fn order(db: &[u8]) -> Order {
    if let Some(o) = crate::nssent::overridden(db) {
        return o;
    }
    let mut path = [0u8; 200];
    conf_path(&mut path);
    let sig = file_sig(&path);
    CACHE.lock.lock_always();
    let tab = unsafe { &mut *CACHE.e.get() };
    let mut slot = None;
    for (i, c) in tab.iter().enumerate() {
        if c.valid && &c.db[..c.dlen as usize] == db {
            slot = Some(i);
            break;
        }
    }
    let i = match slot {
        Some(i) => i,
        None => tab.iter().position(|c| !c.valid).unwrap_or(0),
    };
    let c = &mut tab[i];
    if !(c.valid && &c.db[..c.dlen as usize] == db && c.sig == sig) {
        let o = read_conf(&path, db);
        c.order = o;
        c.sig = sig;
        let n = db.len().min(12);
        c.db[..n].copy_from_slice(&db[..n]);
        c.dlen = n as u8;
        c.valid = true;
    }
    let o = c.order;
    CACHE.lock.unlock_always();
    o
}

struct Mod {
    name: [u8; NAME_MAX],
    len: u8,
    handle: usize,
}

struct Mods {
    lock: RawMutex,
    n: core::cell::UnsafeCell<usize>,
    e: core::cell::UnsafeCell<[Mod; 16]>,
}
unsafe impl Sync for Mods {}

static MODS: Mods = Mods { lock: RawMutex::new(), n: core::cell::UnsafeCell::new(0), e: core::cell::UnsafeCell::new([const { Mod { name: [0; NAME_MAX], len: 0, handle: 0 } }; 16]) };

pub const fn supported() -> bool {
    cfg!(feature = "shared")
}

pub fn module(name: &[u8]) -> usize {
    #[cfg(feature = "shared")]
    unsafe {
        if name.is_empty() || name.len() > NAME_MAX {
            return 0;
        }
        MODS.lock.lock_always();
        let n = &mut *MODS.n.get();
        let tab = &mut *MODS.e.get();
        for m in &tab[..*n] {
            if &m.name[..m.len as usize] == name {
                let h = m.handle;
                MODS.lock.unlock_always();
                return h;
            }
        }
        let mut file = [0u8; 64];
        let pre = b"libnss_";
        let suf = b".so.2\0";
        if pre.len() + name.len() + suf.len() > file.len() {
            MODS.lock.unlock_always();
            return 0;
        }
        file[..pre.len()].copy_from_slice(pre);
        file[pre.len()..pre.len() + name.len()].copy_from_slice(name);
        file[pre.len() + name.len()..pre.len() + name.len() + suf.len()].copy_from_slice(suf);
        let h = dlopen(file.as_ptr() as *const c_char, 1) as usize;
        if *n < tab.len() {
            tab[*n] = Mod { name: [0; NAME_MAX], len: name.len() as u8, handle: h };
            tab[*n].name[..name.len()].copy_from_slice(name);
            *n += 1;
        }
        MODS.lock.unlock_always();
        h
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = name;
        0
    }
}

pub fn function(modname: &[u8], func: &[u8]) -> usize {
    #[cfg(feature = "shared")]
    unsafe {
        let h = module(modname);
        if h == 0 {
            return 0;
        }
        let mut sym = [0u8; 96];
        let pre = b"_nss_";
        let total = pre.len() + modname.len() + 1 + func.len() + 1;
        if total > sym.len() {
            return 0;
        }
        let mut o = 0;
        for part in [&pre[..], modname, b"_", func, b"\0"] {
            sym[o..o + part.len()].copy_from_slice(part);
            o += part.len();
        }
        dlsym(h as *mut c_void, sym.as_ptr() as *const c_char) as usize
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = (modname, func);
        0
    }
}

