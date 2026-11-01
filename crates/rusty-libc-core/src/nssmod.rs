//! Name service switch plug-ins: the `libnss_<name>.so.2` modules of glibc (systemd, myhostname, mdns, sss, winbind, ...).
//!
//! `/etc/nsswitch.conf` names the sources of each database in order (`passwd: files systemd`, `hosts: files myhostname resolve
//! [!UNAVAIL=return] dns`). `files`, `compat` and `dns` are built into this library; every other name is a module that
//! glibc loads with `dlopen("libnss_NAME.so.2")` and whose functions are called as `_nss_NAME_getpwnam_r` and so on. The
//! modules exist only in the shared libc.so.6 (the `shared` feature, where `dlopen` is the loader's); a static program has no
//! `dlopen` and, like a static glibc program, cannot use them: such sources are skipped.
//!
//! This file has the parts every database shares: parsing a `db: source [STATUS=ACTION] ...` line (glibc's nss_parse_service_list,
//! with glibc 2.43 default actions: SUCCESS=return, every other status continue), a cache of the parsed lines
//! that notices a changed file, and the module table (load once, find functions by name).
#![cfg_attr(not(feature = "shared"), allow(dead_code, unused_imports))]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::SyncCell;
use crate::lock::RawMutex;
use core::ffi::{c_char, c_int, c_void};

#[cfg(feature = "shared")]
unsafe extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

/// glibc's `enum nss_status`.
pub const NSS_TRYAGAIN: i32 = -2;
pub const NSS_UNAVAIL: i32 = -1;
pub const NSS_NOTFOUND: i32 = 0;
pub const NSS_SUCCESS: i32 = 1;

/// What to do after a source answered with a status.
pub const ACT_RETURN: u8 = 0;
pub const ACT_CONTINUE: u8 = 1;
pub const ACT_MERGE: u8 = 2;

pub const MAX_SOURCES: usize = 8;
pub const NAME_MAX: usize = 24;

/// `NSS_STATUS_RETURN`, glibc's fifth status (what a module's end-of-group answer is).
pub const NSS_RETURN: i32 = 2;

/// One source of a database and the action for each status (indexed by `status + 2`: TRYAGAIN, UNAVAIL, NOTFOUND, SUCCESS,
/// RETURN). A name longer than `NAME_MAX` is kept empty: such a module can never be loaded.
#[derive(Clone, Copy)]
pub struct Source {
    pub name: [u8; NAME_MAX],
    pub len: u8,
    pub act: [u8; 5],
}

impl Source {
    /// glibc 2.43's defaults (nss/nss_action_parse.c): SUCCESS and RETURN return, every other status continues.
    pub const EMPTY: Source = Source { name: [0; NAME_MAX], len: 0, act: [ACT_CONTINUE, ACT_CONTINUE, ACT_CONTINUE, ACT_RETURN, ACT_RETURN] };
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len as usize]
    }
    pub fn is(&self, n: &[u8]) -> bool {
        self.name().eq_ignore_ascii_case(n)
    }
    /// The built-in sources (`files` and `compat` read the files, `dns` is the resolver).
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

/// Parse the right hand side of a `db:` line the way glibc 2.43 does (`nss_action_parse`, nss/nss_action_parse.c): sources
/// are words, each may be followed by one `[STATUS=ACTION ...]` list (`!` before a status means every status but that one);
/// a bracket where a source name belongs ends the list; a status or action name that is not known, a missing `=`, an
/// unterminated or empty bracket make the whole line invalid (None).
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
                    // every slot (the RETURN status's too) gets the action, then this status gets its old one back
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

/// The list glibc 2.43 uses for a database that nsswitch.conf does not mention (nss/nss_database.c, built without the
/// obsolete NIS code): `files dns` for hosts and networks, nothing for initgroups, `nis` for the *_compat ones,
/// `nis nisplus` for publickey, `files` for the rest.
fn default_spec(db: &[u8]) -> &'static [u8] {
    match db {
        b"hosts" | b"networks" => b"files dns",
        b"initgroups" => b"",
        b"group_compat" | b"passwd_compat" | b"shadow_compat" => b"nis",
        b"publickey" => b"nis nisplus",
        _ => b"files",
    }
}

/// Databases glibc reads from nsswitch.conf (nss/databases.def); lines for other names are ignored.
const KNOWN_DBS: [&[u8]; 17] = [
    b"aliases", b"ethers", b"group", b"group_compat", b"gshadow", b"hosts", b"initgroups", b"netgroup", b"networks", b"passwd", b"passwd_compat", b"protocols", b"publickey", b"rpc", b"services", b"shadow", b"shadow_compat",
];

/// A database with no line of its own takes the line of this one when that is given (shadow follows passwd, gshadow follows
/// group, shadow_compat follows passwd_compat).
fn follows(db: &[u8]) -> Option<&'static [u8]> {
    match db {
        b"shadow" => Some(b"passwd"),
        b"gshadow" => Some(b"group"),
        b"shadow_compat" => Some(b"passwd_compat"),
        _ => None,
    }
}

// ---------------------------------------------------------------- reading nsswitch.conf

/// Path used for the configuration file (tests and the Rust API may point it elsewhere).
static CONF_PATH: LockedPath = LockedPath::new();

struct LockedPath {
    lock: RawMutex,
    /// Only touched with `lock` held (`lock_always`).
    buf: SyncCell<[u8; 200]>,
}
impl LockedPath {
    const fn new() -> LockedPath {
        LockedPath { lock: RawMutex::new(), buf: SyncCell::new([0; 200]) }
    }
}

/// Use `path` (NUL-terminated or not) instead of `/etc/nsswitch.conf`; an empty path restores the default.
pub fn set_conf_path(path: &[u8]) {
    CONF_PATH.lock.lock_always();
    // SAFETY: the lock is held (the rule of `buf`).
    unsafe {
        CONF_PATH.buf.with_unsync(|b| {
            let n = path.len().min(199);
            b[..n].copy_from_slice(&path[..n]);
            b[n] = 0;
        })
    };
    CONF_PATH.lock.unlock_always();
}

fn conf_path(out: &mut [u8; 200]) {
    CONF_PATH.lock.lock_always();
    // SAFETY: the lock is held (the rule of `buf`).
    unsafe {
        CONF_PATH.buf.with_unsync(|b| {
            if b[0] == 0 {
                let d = b"/etc/nsswitch.conf\0";
                out[..d.len()].copy_from_slice(d);
            } else {
                *out = *b;
            }
        })
    };
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
    /// Only touched with `lock` held (`lock_always`).
    e: SyncCell<[Cached; CACHE_DBS]>,
}

static CACHE: Cache = Cache {
    lock: RawMutex::new(),
    e: SyncCell::new([const { Cached { db: [0; 12], dlen: 0, sig: [0; 3], order: Order::EMPTY, valid: false } }; CACHE_DBS]),
};

fn file_sig(path: &[u8; 200]) -> [u64; 3] {
    let mut st = [0u64; 18];
    // SAFETY: `path` is NUL-terminated (`conf_path` writes one); the kernel writes one struct stat (144 bytes) into `st`.
    let r = unsafe { crate::syscall::sys_stat(path.as_ptr() as usize, st.as_mut_ptr() as usize) };
    if let Err(e) = crate::syscall::check(r) {
        // glibc looks at nsswitch.conf with stat() on every lookup (nss_database_check_reload_and_get): a missing file leaves
        // errno ENOENT behind, even when the lookup itself succeeds
        crate::errno::set(e.0);
        return [u64::MAX; 3];
    }
    // x86-64 struct stat: ino at word 1, size at word 6, mtime at words 11 and 12
    [st[1], st[11] ^ (st[6] << 32), st[12]]
}

fn read_conf(path: &[u8; 200], db: &[u8]) -> Order {
    let default = || parse_sources(default_spec(db)).unwrap_or(Order::EMPTY);
    // SAFETY: `path` is NUL-terminated (`conf_path`).
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
    // glibc reads the whole file when it loads the configuration: one line it cannot parse spoils the lot (no database has
    // any source then), a later line for a database replaces an earlier one, and `<db>:` is matched exactly
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

/// The sources of database `db` (`passwd`, `group`, ...): what `__nss_configure_lookup` set, else nsswitch.conf, else glibc's default
/// for the database. `n == 0` means no source at all (an empty list on purpose, or a configuration glibc cannot parse).
/// The parsed line is cached and read again when the file changes.
pub fn order(db: &[u8]) -> Order {
    if let Some(o) = crate::nssent::overridden(db) {
        return o;
    }
    let mut path = [0u8; 200];
    conf_path(&mut path);
    let sig = file_sig(&path);
    CACHE.lock.lock_always();
    // SAFETY: the lock is held until the end of the closure's work (the rule of `e`).
    let o = unsafe { CACHE.e.with_unsync(|tab| order_locked(tab, db, &path, sig)) };
    CACHE.lock.unlock_always();
    o
}

/// The cache lookup of [`order`], with the cache's lock held.
fn order_locked(tab: &mut [Cached; CACHE_DBS], db: &[u8], path: &[u8; 200], sig: [u64; 3]) -> Order {
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
        // (reading takes a while: the lock is only a guard against two threads filling the same slot)
        let o = read_conf(path, db);
        c.order = o;
        c.sig = sig;
        let n = db.len().min(12);
        c.db[..n].copy_from_slice(&db[..n]);
        c.dlen = n as u8;
        c.valid = true;
    }
    c.order
}

// ---------------------------------------------------------------- modules

struct Mod {
    name: [u8; NAME_MAX],
    len: u8,
    handle: usize,
}

struct Mods {
    lock: RawMutex,
    /// Loaded modules `e[..n]`; only touched with `lock` held (`lock_always`).
    tab: SyncCell<(usize, [Mod; 16])>,
}

static MODS: Mods = Mods { lock: RawMutex::new(), tab: SyncCell::new((0, [const { Mod { name: [0; NAME_MAX], len: 0, handle: 0 } }; 16])) };

/// Can this build load modules at all?
pub const fn supported() -> bool {
    cfg!(feature = "shared")
}

/// The handle of `libnss_<name>.so.2`, loading it the first time; 0 if it is not installed or cannot be loaded (a failure is
/// remembered, like glibc's). Always 0 outside the shared libc.
pub fn module(name: &[u8]) -> usize {
    #[cfg(feature = "shared")]
    {
        if name.is_empty() || name.len() > NAME_MAX {
            return 0;
        }
        MODS.lock.lock_always();
        // SAFETY: the lock is held for the whole closure (the rule of `tab`), loading included, as before.
        let h = unsafe { MODS.tab.with_unsync(|(n, tab)| module_locked(n, tab, name)) };
        MODS.lock.unlock_always();
        h
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = name;
        0
    }
}

/// [`module`] with the table's lock held.
#[cfg(feature = "shared")]
fn module_locked(n: &mut usize, tab: &mut [Mod; 16], name: &[u8]) -> usize {
    for m in &tab[..*n] {
        if &m.name[..m.len as usize] == name {
            return m.handle;
        }
    }
    let mut file = [0u8; 64];
    let pre = b"libnss_";
    let suf = b".so.2\0";
    if pre.len() + name.len() + suf.len() > file.len() {
        return 0;
    }
    file[..pre.len()].copy_from_slice(pre);
    file[pre.len()..pre.len() + name.len()].copy_from_slice(name);
    file[pre.len() + name.len()..pre.len() + name.len() + suf.len()].copy_from_slice(suf);
    // RTLD_LAZY: the module's own dependencies resolve on first use, as glibc loads them. errno stays as the caller left
    // it: loading (the module's constructors, a failed search of the library path) may change it, and glibc's
    // __nss_module_get_function puts it back whether the load worked or not
    let saved = crate::errno::get();
    // SAFETY: `file` is a NUL-terminated name; dlopen is the loader's.
    let h = unsafe { dlopen(file.as_ptr() as *const c_char, 1) } as usize;
    crate::errno::set(saved);
    if *n < tab.len() {
        tab[*n] = Mod { name: [0; NAME_MAX], len: name.len() as u8, handle: h };
        tab[*n].name[..name.len()].copy_from_slice(name);
        *n += 1;
    }
    h
}

/// The address of `_nss_<module>_<func>` (for example `getpwnam_r`), or 0.
pub fn function(modname: &[u8], func: &[u8]) -> usize {
    #[cfg(feature = "shared")]
    {
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
        // the lookup leaves errno alone too (glibc resolves the functions while loading, under the same saved errno)
        let saved = crate::errno::get();
        // SAFETY: `h` is a handle dlopen returned (never closed); `sym` is NUL-terminated.
        let f = unsafe { dlsym(h as *mut c_void, sym.as_ptr() as *const c_char) } as usize;
        crate::errno::set(saved);
        f
    }
    #[cfg(not(feature = "shared"))]
    {
        let _ = (modname, func);
        0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use std::sync::Mutex;

    static CONF_LOCK: Mutex<()> = Mutex::new(());

    fn p(spec: &[u8]) -> Order {
        parse_sources(spec).expect("valid line")
    }

    #[test]
    fn parses_fedoras_hosts_line() {
        let o = p(b" files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns ");
        assert_eq!(o.n, 5);
        let names: [&[u8]; 5] = [b"files", b"myhostname", b"mdns4_minimal", b"resolve", b"dns"];
        for (i, n) in names.iter().enumerate() {
            assert_eq!(o.e[i].name(), *n);
        }
        // defaults (glibc 2.43, nss_action_parse.c): SUCCESS and RETURN return, everything else continues
        assert_eq!(o.e[0].action(NSS_SUCCESS), ACT_RETURN);
        assert_eq!(o.e[0].action(NSS_NOTFOUND), ACT_CONTINUE);
        assert_eq!(o.e[0].action(NSS_UNAVAIL), ACT_CONTINUE);
        assert_eq!(o.e[0].action(NSS_TRYAGAIN), ACT_CONTINUE);
        assert_eq!(o.e[0].action(NSS_RETURN), ACT_RETURN);
        // mdns4_minimal [NOTFOUND=return]
        assert_eq!(o.e[2].action(NSS_NOTFOUND), ACT_RETURN);
        assert_eq!(o.e[2].action(NSS_UNAVAIL), ACT_CONTINUE);
        // resolve [!UNAVAIL=return]: every status but UNAVAIL returns
        assert_eq!(o.e[3].action(NSS_UNAVAIL), ACT_CONTINUE);
        assert_eq!(o.e[3].action(NSS_NOTFOUND), ACT_RETURN);
        assert_eq!(o.e[3].action(NSS_TRYAGAIN), ACT_RETURN);
        assert_eq!(o.e[3].action(NSS_SUCCESS), ACT_RETURN);
    }

    #[test]
    fn merge_and_case() {
        let o = p(b"files [SUCCESS=merge] systemd [notfound=Continue Unavail=RETURN]");
        assert_eq!(o.n, 2);
        assert_eq!(o.e[0].action(NSS_SUCCESS), ACT_MERGE);
        assert!(o.e[0].is(b"FILES") && o.e[0].is_builtin());
        assert!(!o.e[1].is_builtin());
        assert_eq!(o.e[1].action(NSS_UNAVAIL), ACT_RETURN);
    }

    /// nss_action_parse.c returns false (EINVAL) for all of these: the whole line is invalid.
    #[test]
    fn invalid_status_or_action_rejects_the_whole_line() {
        for bad in [
            &b"files [bogus=return]"[..],
            b"files [SUCCESS]",
            b"files [SUCCESS=]",
            b"files [SUCCESS=bogus]",
            b"files [SUCCESS=return",
            b"files [SUCCESS=return NOTFOUND]",
            b"files []",
            b"files [ ]",
            b"files [!=return]",
            b"files [SUCCESSS=return]",
            b"files [SUCCES=return]",
            b"files [success = return] systemd [x=y]",
            b"files systemd [NOTFOUND=retur]",
            b"files [=return]",
        ] {
            assert!(parse_sources(bad).is_none(), "{:?}", std::str::from_utf8(bad));
        }
        // blanks around the pieces are fine
        assert!(parse_sources(b"files [ success = return  notfound=continue ] systemd").is_some());
        assert!(parse_sources(b"files [!success=return]").is_some());
    }

    /// A bracket where a source name belongs (first, or after another bracket) ends the list without an error.
    #[test]
    fn a_bracket_in_place_of_a_name_ends_the_list() {
        assert_eq!(p(b"[SUCCESS=continue] files").n, 0);
        let o = p(b"files [SUCCESS=return] [NOTFOUND=return] systemd");
        assert_eq!(o.n, 1);
        assert_eq!(p(b"").n, 0);
        assert_eq!(p(b"   ").n, 0);
    }

    /// `[!X=act]` sets every slot, the RETURN status's included, to `act` and gives X its old action back.
    #[test]
    fn negation_covers_the_return_slot() {
        let o = p(b"a [!NOTFOUND=continue] b [!SUCCESS=return] c [SUCCESS=continue] d [!UNAVAIL=merge]");
        // [!NOTFOUND=continue]: SUCCESS and RETURN now continue, NOTFOUND keeps its default (continue)
        assert_eq!(o.e[0].act, [ACT_CONTINUE; 5]);
        // [!SUCCESS=return]: all return but SUCCESS keeps its default (return)
        assert_eq!(o.e[1].act, [ACT_RETURN; 5]);
        // a plain [SUCCESS=continue] leaves the RETURN slot alone
        assert_eq!(o.e[2].action(NSS_SUCCESS), ACT_CONTINUE);
        assert_eq!(o.e[2].action(NSS_RETURN), ACT_RETURN);
        // [!UNAVAIL=merge]: merge everywhere but UNAVAIL (default continue)
        assert_eq!(o.e[3].act, [ACT_MERGE, ACT_CONTINUE, ACT_MERGE, ACT_MERGE, ACT_MERGE]);
    }

    #[test]
    fn too_many_sources_are_dropped() {
        let o = p(b"a b c d e f g h i j");
        assert_eq!(o.n, MAX_SOURCES);
    }

    fn with_conf<R>(text: &str, f: impl FnOnce() -> R) -> R {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let _g = CONF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = std::env::temp_dir().join(format!("nssmod-conf-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::write(&path, text).unwrap();
        set_conf_path(path.to_str().unwrap().as_bytes());
        let r = f();
        set_conf_path(b"");
        let _ = std::fs::remove_file(&path);
        r
    }

    fn names(o: &Order) -> Vec<String> {
        o.e[..o.n].iter().map(|s| String::from_utf8_lossy(s.name()).into_owned()).collect()
    }

    #[test]
    fn nsswitch_conf_is_read_like_glibc() {
        // the last line for a database wins, names are exact, other databases are ignored
        with_conf("passwd: files\nPASSWD: nope\npasswd: files systemd\nautomount: whatever [broken\nhosts:files  dns\n", || {
            assert_eq!(names(&order(b"passwd")), ["files", "systemd"]);
            assert_eq!(names(&order(b"hosts")), ["files", "dns"]);
            // not mentioned: shadow follows passwd, gshadow follows group (default files), initgroups is empty, services files
            assert_eq!(names(&order(b"shadow")), ["files", "systemd"]);
            assert_eq!(names(&order(b"gshadow")), ["files"]);
            assert_eq!(order(b"initgroups").n, 0);
            assert_eq!(names(&order(b"services")), ["files"]);
            assert_eq!(names(&order(b"networks")), ["files", "dns"]);
        });
    }

    #[test]
    fn a_line_glibc_cannot_parse_spoils_the_whole_configuration() {
        // one unparsable line of a known database: every database ends up with no source (glibc: all lookups fail)
        with_conf("passwd: files\ngroup: files [SUCCESS=bogus] systemd\nhosts: files dns\n", || {
            for db in [&b"passwd"[..], b"group", b"hosts", b"services"] {
                assert_eq!(order(db).n, 0, "{}", String::from_utf8_lossy(db));
            }
        });
    }

    #[test]
    fn a_missing_file_means_the_defaults() {
        let _g = CONF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_conf_path(b"/nonexistent-dir/nsswitch.conf");
        assert_eq!(names(&order(b"passwd")), ["files"]);
        assert_eq!(names(&order(b"hosts")), ["files", "dns"]);
        assert_eq!(order(b"initgroups").n, 0);
        assert_eq!(names(&order(b"publickey")), ["nis", "nisplus"]);
        set_conf_path(b"");
    }
}
