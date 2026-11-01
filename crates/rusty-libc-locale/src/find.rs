//! Finding the data of one category for a locale name, the way glibc's `_nl_find_locale` does
//! (locale/findlocale.c, intl/l10nflist.c, intl/explodename.c, intl/localealias.c; LGPL; the
//! behaviour here was also checked against the host's glibc, see the tests).
//!
//! In order: an empty name means the environment (LC_ALL, LC_<category>, LANG); "C" and "POSIX"
//! are built in; otherwise, without LOCPATH, the name is looked up in the locale archive (with the
//! codeset part normalised: `en_US.UTF-8` is the archive's `en_US.utf8`), then as an alias from
//! /usr/share/locale/locale.alias; then the per-locale directories are tried for the name and for
//! progressively less specific forms (dropping codeset, territory, modifier), and a locale found
//! that way must have the codeset the name asked for.
use crate::archive;
use crate::charsets::same_charset;
use crate::data;
use crate::mem;
use core::ffi::c_int;
use core::sync::atomic::{AtomicPtr, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::locale::CatData;

pub const CAT_NAMES: [&str; 13] = [
    "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_ALL", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE",
    "LC_MEASUREMENT", "LC_IDENTIFICATION",
];

/// A locale name (at most 255 bytes, as glibc allows).
#[derive(Clone, Copy)]
pub struct NameBuf {
    b: [u8; 288],
    n: usize,
}

impl NameBuf {
    pub fn new(s: &[u8]) -> NameBuf {
        let mut b = [0u8; 288];
        let n = s.len().min(287);
        b[..n].copy_from_slice(&s[..n]);
        NameBuf { b, n }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

/// Environment value `name`, if set and non-empty.
pub fn env(name: &[u8]) -> Option<&'static [u8]> {
    // SAFETY: the environment block is valid for the program's life.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-NULL getenv result is a NUL-terminated value in the environment block, which is never freed (setenv
    // keeps the strings it replaces).
    let v = unsafe { rusty_libc_core::ffi::cstr_bytes_scalar(p) };
    if v.is_empty() { None } else { Some(v) }
}

/// The name the environment selects for `cat`: LC_ALL, then LC_<cat>, then LANG, else "C".
pub fn env_name(cat: usize) -> &'static [u8] {
    if let Some(v) = env(b"LC_ALL") {
        return v;
    }
    if let Some(v) = env(CAT_NAMES[cat].as_bytes()) {
        return v;
    }
    env(b"LANG").unwrap_or(b"C")
}

fn valid_name(name: &[u8]) -> bool {
    let n = name.len();
    if n > 255 {
        return false;
    }
    if name.windows(4).any(|w| w == b"/../") {
        return false;
    }
    if n == 2 && name == b".." {
        return false;
    }
    if n >= 3 && (name.starts_with(b"../") || name.ends_with(b"/..")) {
        return false;
    }
    if name.contains(&b'/') && name[0] != b'/' {
        return false;
    }
    true
}

/// glibc's `_nl_normalize_codeset`: letters lower-cased, digits kept, everything else dropped; a
/// name of digits only gets an "iso" prefix.
pub fn normalize_codeset(cs: &[u8]) -> NameBuf {
    let only_digit = cs.iter().filter(|c| c.is_ascii_alphanumeric()).all(|c| c.is_ascii_digit());
    let mut out = NameBuf::new(b"");
    if only_digit {
        out.b[..3].copy_from_slice(b"iso");
        out.n = 3;
    }
    for &c in cs {
        if out.n >= 286 {
            break;
        }
        if c.is_ascii_alphabetic() {
            out.b[out.n] = c.to_ascii_lowercase();
            out.n += 1;
        } else if c.is_ascii_digit() {
            out.b[out.n] = c;
            out.n += 1;
        }
    }
    out
}

const XPG_NORM_CODESET: u32 = 1;
const XPG_CODESET: u32 = 2;
const XPG_TERRITORY: u32 = 4;
const XPG_MODIFIER: u32 = 8;

struct Parts<'a> {
    language: &'a [u8],
    territory: Option<&'a [u8]>,
    codeset: Option<&'a [u8]>,
    ncs: NameBuf,
    modifier: Option<&'a [u8]>,
    mask: u32,
}

/// glibc's `_nl_explode_name`: language[_territory][.codeset][@modifier].
fn explode(name: &[u8]) -> Parts<'_> {
    let mut p = Parts { language: name, territory: None, codeset: None, ncs: NameBuf::new(b""), modifier: None, mask: 0 };
    let lend = name.iter().position(|&c| matches!(c, b'_' | b'@' | b'.')).unwrap_or(name.len());
    let mut rest: &[u8] = &name[name.len()..];
    if lend != 0 {
        p.language = &name[..lend];
        rest = &name[lend..];
        if rest.first() == Some(&b'_') {
            let e = rest[1..].iter().position(|&c| matches!(c, b'.' | b'@')).map_or(rest.len(), |i| i + 1);
            p.territory = Some(&rest[1..e]);
            rest = &rest[e..];
            p.mask |= XPG_TERRITORY;
        }
        if rest.first() == Some(&b'.') {
            let e = rest[1..].iter().position(|&c| c == b'@').map_or(rest.len(), |i| i + 1);
            let cs = &rest[1..e];
            p.codeset = Some(cs);
            rest = &rest[e..];
            p.mask |= XPG_CODESET;
            if !cs.is_empty() {
                let n = normalize_codeset(cs);
                if n.as_bytes() != cs {
                    p.ncs = n;
                    p.mask |= XPG_NORM_CODESET;
                }
            }
        }
    }
    if rest.first() == Some(&b'@') {
        let m = &rest[1..];
        p.modifier = Some(m);
        if !m.is_empty() {
            p.mask |= XPG_MODIFIER;
        }
    }
    if p.territory == Some(b"") {
        p.mask &= !XPG_TERRITORY;
    }
    if p.codeset == Some(b"") {
        p.mask &= !XPG_CODESET;
    }
    p
}

// ---- locale.alias ----

struct AliasTable {
    text: &'static [u8],
    /// (alias start, alias length, value start, value length) into `text`, sorted by alias ignoring case
    ent: &'static [[usize; 4]],
}

/// The parsed locale.alias: null until first needed, then a table that is never freed or changed (NO_ALIASES when the
/// file is missing). setlocale (under the locale lock) and gettext (under its own lock) both read it, so it is set once
/// with a compare-exchange; a thread that loses the race drops its copy (leaked: a rare race, a few kilobytes).
static ALIASES: AtomicPtr<AliasTable> = AtomicPtr::new(core::ptr::null_mut());
static NO_ALIASES: AliasTable = AliasTable { text: &[], ent: &[] };

fn load_aliases() -> &'static AliasTable {
    let p = ALIASES.load(Ordering::Acquire);
    // SAFETY: ALIASES holds null or a pointer to NO_ALIASES or to a table leaked by `read_aliases`, never freed or changed.
    if let Some(t) = unsafe { p.as_ref() } {
        return t;
    }
    let new: &'static AliasTable = match read_aliases() {
        Some(t) => t,
        None => &NO_ALIASES,
    };
    match ALIASES.compare_exchange(core::ptr::null_mut(), new as *const AliasTable as *mut AliasTable, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new,
        // SAFETY: as above (another thread stored it).
        Err(other) => unsafe { &*other },
    }
}

fn read_aliases() -> Option<&'static AliasTable> {
    let text = archive::map_file(b"/usr/share/locale/locale.alias\0", None)?;
    let len = text.len();
    let cap = text.iter().filter(|&&c| c == b'\n').count() + 1;
    let ent = mem::leak_default::<[usize; 4]>(cap)?;
    let mut n = 0;
    let isspace = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let mut pos = 0;
    while pos < len {
        let eol = text[pos..].iter().position(|&c| c == b'\n').map_or(len, |i| pos + i);
        let mut line = &text[pos..eol];
        // glibc reads lines of at most 399 bytes and ignores the rest of a longer line
        if line.len() > 399 {
            line = &line[..399];
        }
        let base = pos;
        pos = eol + 1;
        let mut i = 0;
        while i < line.len() && isspace(line[i]) {
            i += 1;
        }
        if i >= line.len() || line[i] == b'#' {
            continue;
        }
        let a0 = i;
        while i < line.len() && !isspace(line[i]) {
            i += 1;
        }
        let a1 = i;
        while i < line.len() && isspace(line[i]) {
            i += 1;
        }
        if i >= line.len() {
            continue;
        }
        let v0 = i;
        while i < line.len() && !isspace(line[i]) {
            i += 1;
        }
        ent[n] = [base + a0, a1 - a0, base + v0, i - v0];
        n += 1;
    }
    // sort by alias, ignoring case (insertion sort keeps equal keys in file order)
    let e = &mut ent[..n];
    for i in 1..n {
        let mut j = i;
        while j > 0 && cmp_nocase(&text[e[j - 1][0]..e[j - 1][0] + e[j - 1][1]], &text[e[j][0]..e[j][0] + e[j][1]]) == core::cmp::Ordering::Greater {
            e.swap(j - 1, j);
            j -= 1;
        }
    }
    let ent: &'static [[usize; 4]] = &ent[..n];
    mem::leak(AliasTable { text, ent }).map(|t| &*t)
}

fn cmp_nocase(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let mut i = 0;
    loop {
        let x = a.get(i).map_or(0, |c| c.to_ascii_lowercase());
        let y = b.get(i).map_or(0, |c| c.to_ascii_lowercase());
        if x != y {
            return x.cmp(&y);
        }
        if x == 0 {
            return core::cmp::Ordering::Equal;
        }
        i += 1;
    }
}

/// `_nl_expand_alias`: the value `name` stands for in locale.alias (case-insensitive), if any.
pub fn expand_alias(name: &[u8]) -> Option<NameBuf> {
    let t = load_aliases();
    let (text, e) = (t.text, t.ent);
    let (mut lo, mut hi) = (0, e.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        match cmp_nocase(&text[e[mid][0]..e[mid][0] + e[mid][1]], name) {
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
            core::cmp::Ordering::Equal => return Some(NameBuf::new(&text[e[mid][2]..e[mid][2] + e[mid][3]])),
        }
    }
    None
}

// ---- archive and directory lookup ----

/// Look `name` up in the archive (codeset normalised first) and intern the category.
fn from_archive(cat: usize, name: &[u8]) -> Option<&'static CatData> {
    let mut nb = NameBuf::new(name);
    if let Some(dot) = name.iter().position(|&c| c == b'.') {
        let after = &name[dot + 1..];
        if !after.is_empty() && after[0] != b'@' {
            let rest = after.iter().position(|&c| c == b'@').unwrap_or(after.len());
            let ncs = normalize_codeset(&after[..rest]);
            if ncs.as_bytes() != &after[..rest] {
                let mut out = [0u8; 288];
                let mut n = dot + 1;
                out[..n].copy_from_slice(&name[..n]);
                out[n..n + ncs.n].copy_from_slice(ncs.as_bytes());
                n += ncs.n;
                let tail = &after[rest..];
                if n + tail.len() < out.len() {
                    out[n..n + tail.len()].copy_from_slice(tail);
                    n += tail.len();
                }
                nb = NameBuf::new(&out[..n]);
            }
        }
    }
    let recs = archive::lookup(nb.as_bytes())?;
    data::intern(cat, recs[cat])
}

fn from_dirs(cat: usize, work: &[u8], locpath: Option<&[u8]>) -> Result<&'static CatData, c_int> {
    let p = explode(work);
    let mut dirs: [&[u8]; 32] = [b""; 32];
    let mut nd = 0;
    if let Some(lp) = locpath {
        for d in lp.split(|&c| c == b':') {
            // an empty entry is skipped (argz_create_sep drops empty fields)
            if !d.is_empty() && nd < 31 {
                dirs[nd] = d;
                nd += 1;
            }
        }
    }
    dirs[nd] = archive::DEFAULT_DIR;
    nd += 1;
    let catname = CAT_NAMES[cat].as_bytes();
    let mut cnt = p.mask as i32;
    while cnt >= 0 {
        let c = cnt as u32;
        cnt -= 1;
        if c & !p.mask != 0 {
            continue;
        }
        if c & XPG_CODESET != 0 && c & XPG_NORM_CODESET != 0 {
            continue; // glibc never loads this pseudo entry
        }
        for d in &dirs[..nd] {
            let mut path = [0u8; 700];
            let mut n = 0;
            let mut put = |s: &[u8], n: &mut usize| -> bool {
                if *n + s.len() >= path.len() - 1 {
                    return false;
                }
                path[*n..*n + s.len()].copy_from_slice(s);
                *n += s.len();
                true
            };
            let mut ok = put(d, &mut n) && put(b"/", &mut n) && put(p.language, &mut n);
            if c & XPG_TERRITORY != 0 {
                ok = ok && put(b"_", &mut n) && put(p.territory.unwrap_or(b""), &mut n);
            }
            if c & XPG_CODESET != 0 {
                ok = ok && put(b".", &mut n) && put(p.codeset.unwrap_or(b""), &mut n);
            }
            if c & XPG_NORM_CODESET != 0 {
                ok = ok && put(b".", &mut n) && put(p.ncs.as_bytes(), &mut n);
            }
            if c & XPG_MODIFIER != 0 {
                ok = ok && put(b"@", &mut n) && put(p.modifier.unwrap_or(b""), &mut n);
            }
            ok = ok && put(b"/", &mut n) && put(catname, &mut n);
            if !ok {
                continue;
            }
            path[n] = 0;
            let Some(img) = archive::map_file_cached(&path[..=n], Some(catname)) else { continue };
            let Some(d) = data::intern(cat, img) else { continue };
            // a name that spells a codeset must get a locale with that codeset
            if let Some(cs) = p.codeset {
                let have = d.bytes(data::CODESET_IDX[cat]);
                if !same_charset(cs, have) {
                    return Err(errno::ENOENT);
                }
            }
            return Ok(d);
        }
    }
    Err(errno::ENOENT)
}

/// The names glibc's `_nl_make_l10nflist` tries for the locale name `work` (language[_territory]
/// [.codeset][@modifier]) below `dir`: `dir/<name>/<tail>` for the full name first, then for the
/// forms with less information (dropping modifier, territory, codeset in glibc's order). `f`
/// gets each path (NUL-terminated) and stops the walk by returning true.
pub fn for_each_candidate(work: &[u8], dir: &[u8], tail: &[u8], mut f: impl FnMut(&[u8]) -> bool) {
    let p = explode(work);
    let mut cnt = p.mask as i32;
    while cnt >= 0 {
        let c = cnt as u32;
        cnt -= 1;
        if c & !p.mask != 0 {
            continue;
        }
        if c & XPG_CODESET != 0 && c & XPG_NORM_CODESET != 0 {
            continue;
        }
        let mut path = [0u8; 700];
        let mut n = 0;
        let mut put = |s: &[u8], n: &mut usize| -> bool {
            if *n + s.len() >= path.len() - 1 {
                return false;
            }
            path[*n..*n + s.len()].copy_from_slice(s);
            *n += s.len();
            true
        };
        let mut ok = put(dir, &mut n) && put(b"/", &mut n) && put(p.language, &mut n);
        if c & XPG_TERRITORY != 0 {
            ok = ok && put(b"_", &mut n) && put(p.territory.unwrap_or(b""), &mut n);
        }
        if c & XPG_CODESET != 0 {
            ok = ok && put(b".", &mut n) && put(p.codeset.unwrap_or(b""), &mut n);
        }
        if c & XPG_NORM_CODESET != 0 {
            ok = ok && put(b".", &mut n) && put(p.ncs.as_bytes(), &mut n);
        }
        if c & XPG_MODIFIER != 0 {
            ok = ok && put(b"@", &mut n) && put(p.modifier.unwrap_or(b""), &mut n);
        }
        ok = ok && put(b"/", &mut n) && put(tail, &mut n);
        if !ok {
            continue;
        }
        path[n] = 0;
        if f(&path[..=n]) {
            return;
        }
    }
}

/// What a name resolves to.
pub struct Found {
    pub data: &'static CatData,
    /// The name to report: the one given (or the environment's), "C" for C and POSIX.
    pub name: NameBuf,
}

/// `_nl_find_locale` for one category; `name` empty means "from the environment". Errors are errno
/// values (EINVAL for a bad name, ENOENT when nothing matches). Callers hold the locale lock.
pub fn find_locale(cat: usize, name: &[u8], locpath: Option<&[u8]>) -> Result<Found, c_int> {
    let cloc: &[u8] = if name.is_empty() { env_name(cat) } else { name };
    if cloc == b"C" || cloc == b"POSIX" {
        return Ok(Found { data: data::builtin(false, cat), name: NameBuf::new(b"C") });
    }
    if !valid_name(cloc) {
        return Err(errno::EINVAL);
    }
    let given = NameBuf::new(cloc);
    let alias;
    if locpath.is_none() {
        if let Some(d) = from_archive(cat, cloc) {
            return Ok(Found { data: d, name: given });
        }
        alias = expand_alias(cloc);
        if let Some(a) = &alias
            && let Some(d) = from_archive(cat, a.as_bytes())
        {
            return Ok(Found { data: d, name: given });
        }
    } else {
        alias = expand_alias(cloc);
    }
    let work = match &alias {
        Some(a) => *a,
        None => given,
    };
    let d = from_dirs(cat, work.as_bytes(), locpath)?;
    Ok(Found { data: d, name: given })
}
