//! Charset names: glibc's normalisation (upper case, only letters, digits and `_-.,:` kept, exactly
//! two slashes), the `//TRANSLIT` and `//IGNORE` suffixes, and the alias table.
use crate::charsets_gen::{ALIASES, SBS, SPECIAL_CODES, SPECIAL_STRS};
#[cfg(test)]
use crate::charsets_gen::SPECIAL_NAMES;
use crate::unicode::Sb;

/// A charset the converter knows.
#[derive(Clone, Copy)]
pub enum Cs {
    /// A hand-written charset (index into `SPECIAL_NAMES`).
    Special(u8),
    /// A single-byte table charset.
    Sb(&'static Sb),
}

pub const SP_INTERNAL: u8 = 15;

/// A parsed `iconv_open` argument.
pub struct Parsed {
    /// Normalised name with two slashes, e.g. `UTF-8//` (NUL-padded buffer and length).
    pub buf: [u8; 128],
    pub len: usize,
    pub translit: bool,
    pub ignore: bool,
}

impl Parsed {
    pub fn key(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn find_suffix(s: &[u8]) -> Option<usize> {
    let mut slashes = 0;
    let mut term = None;
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'/' => {
                slashes += 1;
                term = Some(i);
            }
            b',' => term = Some(i),
            _ => {}
        }
    }
    if slashes >= 2 { term } else { None }
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn eq_nocase(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// glibc's `__gconv_create_spec` for one name: strip the suffixes (recording TRANSLIT and IGNORE),
/// then normalise. `None` when the name is too long to be any charset.
pub fn parse(name: &[u8]) -> Option<Parsed> {
    if name.len() > 120 {
        return None;
    }
    let mut work = [0u8; 128];
    work[..name.len()].copy_from_slice(name);
    let mut len = name.len();
    let (mut translit, mut ignore) = (false, false);
    loop {
        while len > 0 && (is_space(work[len - 1]) || work[len - 1] == b',' || work[len - 1] == b'/') {
            len -= 1;
        }
        if len == 0 {
            break;
        }
        match find_suffix(&work[..len]) {
            None => break,
            Some(p) => {
                let suf = &work[p..len];
                if eq_nocase(suf, b"/TRANSLIT") || eq_nocase(suf, b",TRANSLIT") {
                    translit = true;
                }
                if eq_nocase(suf, b"/IGNORE") || eq_nocase(suf, b",IGNORE") {
                    ignore = true;
                }
                len = p;
            }
        }
    }
    // strip: keep alphanumerics and _-.,: (upper-cased), at most two slashes, pad to two
    let mut buf = [0u8; 128];
    let mut n = 0;
    let mut slashes = 0;
    for &c in &work[..len] {
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b',' | b':') {
            buf[n] = c.to_ascii_uppercase();
            n += 1;
        } else if c == b'/' {
            slashes += 1;
            if slashes == 3 {
                break;
            }
            buf[n] = b'/';
            n += 1;
        }
    }
    while slashes < 2 {
        buf[n] = b'/';
        n += 1;
        slashes += 1;
    }
    Some(Parsed { buf, len: n, translit, ignore })
}

/// The alias-table key of a `fopen (..., ",ccs=NAME")` charset, as glibc 2.43's `_IO_new_file_fopen` (libio/fileops.c) forms
/// it: `strip` (iconv/gconv_charset.h) of NAME, used as it is: alphanumerics and `_-.,:` kept upper-cased, everything else
/// dropped, the scan stopping at a third slash, then slashes added up to two. No `//TRANSLIT`-style suffix is taken off
/// (`UTF-8//TRANSLIT` stays that key, which no charset has) and an empty result does not mean the locale's charset (glibc
/// then looks up the upper-cased raw text, which never names a charset either). None when the key cannot be a charset name
/// (empty, or longer than any name).
pub fn ccs_key(name: &[u8]) -> Option<Parsed> {
    let mut buf = [0u8; 128];
    let mut n = 0;
    let mut slashes = 0;
    for &c in name {
        let out = if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b',' | b':') {
            c.to_ascii_uppercase()
        } else if c == b'/' {
            slashes += 1;
            if slashes == 3 {
                break;
            }
            b'/'
        } else {
            continue;
        };
        // (two bytes stay free for the padding slashes)
        if n + 2 >= buf.len() {
            return None;
        }
        buf[n] = out;
        n += 1;
    }
    while slashes < 2 {
        buf[n] = b'/';
        n += 1;
        slashes += 1;
    }
    if n == 2 {
        return None;
    }
    Some(Parsed { buf, len: n, translit: false, ignore: false })
}

/// Look a normalised name up in the alias table.
pub fn lookup_key(key: &[u8]) -> Option<Cs> {
    let i = ALIASES.find(key)?;
    Some(code_cs(ALIASES.code(i)))
}

fn code_cs(code: u16) -> Cs {
    if code >= 0x8000 { Cs::Special((code - 0x8000) as u8) } else { Cs::Sb(&SBS[code as usize]) }
}

/// The name of a charset as the module list gives it (without the trailing slashes).
pub fn cs_name(cs: Cs) -> &'static str {
    match cs {
        Cs::Special(k) => SPECIAL_CODES.iter().position(|&c| c == k).map_or("?", |i| SPECIAL_STRS.get(i)),
        Cs::Sb(t) => t.name(),
    }
}

/// The canonical name of any charset name glibc knows, or `None`: `canonical_name("latin1")` is
/// `Some("ISO-8859-1")`. Suffixes are ignored. An empty name means the locale charset (always the
/// C locale's `ANSI_X3.4-1968` here).
pub fn canonical_name(name: &str) -> Option<&'static str> {
    let p = parse(name.as_bytes())?;
    let cs = if p.key() == b"//" { lookup_key(b"ANSI_X3.4-1968//")? } else { lookup_key(p.key())? };
    Some(cs_name(cs))
}

/// Every name `iconv -l` would print (aliases included, with the trailing `//`), sorted.
pub fn all_names() -> impl Iterator<Item = &'static str> {
    // (INTERNAL opens, but glibc keeps it out of the list)
    ALIASES.names().filter(|n| !n.starts_with("INTERNAL"))
}

/// The canonical names of every charset this library implements (for tests and listings).
#[cfg(test)]
pub fn implemented() -> impl Iterator<Item = &'static str> {
    SBS.iter().map(|t| t.name()).chain(SPECIAL_NAMES.iter().filter(|e| e.0 != SP_INTERNAL).map(|e| e.1))
}
