use crate::charsets_gen::{ALIASES, SBS, SPECIAL_NAMES};
use crate::unicode::Sb;

#[derive(Clone, Copy)]
pub enum Cs {
    Special(u8),
    Sb(&'static Sb),
}

pub const SP_INTERNAL: u8 = 15;

pub struct Parsed {
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

pub fn lookup_key(key: &[u8]) -> Option<Cs> {
    let i = ALIASES.find(key)?;
    Some(code_cs(ALIASES.code(i)))
}

fn code_cs(code: u16) -> Cs {
    if code >= 0x8000 { Cs::Special((code - 0x8000) as u8) } else { Cs::Sb(&SBS[code as usize]) }
}

pub fn cs_name(cs: Cs) -> &'static str {
    match cs {
        Cs::Special(k) => SPECIAL_NAMES.iter().find(|e| e.0 == k).map_or("?", |e| e.1),
        Cs::Sb(t) => t.name(),
    }
}

pub fn canonical_name(name: &str) -> Option<&'static str> {
    let p = parse(name.as_bytes())?;
    let cs = if p.key() == b"//" { lookup_key(b"ANSI_X3.4-1968//")? } else { lookup_key(p.key())? };
    Some(cs_name(cs))
}

pub fn all_names() -> impl Iterator<Item = &'static str> {
    ALIASES.names().filter(|n| !n.starts_with("INTERNAL"))
}

