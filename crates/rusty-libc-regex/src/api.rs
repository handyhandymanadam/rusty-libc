use crate::charset;
use crate::consts::*;
use crate::exec::{self, Env, Reg};
use crate::nfa::{self, Nfa};
use crate::parse;
use crate::vec::V;

pub const MAGIC: u64 = 0x5265_4772_6578_0001;

pub struct Compiled {
    pub magic: u64,
    pub nfa: Nfa,
    pub fastmap: [u8; 256],
    pub can_be_null: bool,
    pub xlat: [u8; 256],
    pub lit: [u8; 32],
    pub lit_len: u8,
    pub lit_anchor: u8,
}

fn plain_literal(pattern: &[u8], syntax: u64, mb: charset::Mb) -> Option<([u8; 32], u8, u8)> {
    let flags = RE_ICASE | RE_DOT_NEWLINE | RE_HAT_LISTS_NOT_NEWLINE | RE_NO_SUB;
    let base = syntax & !flags;
    if syntax & RE_ICASE != 0 || (base != (RE_SYNTAX_POSIX_EXTENDED & !flags) && base != (RE_SYNTAX_POSIX_BASIC & !flags)) || mb == charset::Mb::Other {
        return None;
    }
    let mut anchor = 0u8;
    let mut pattern = pattern;
    if let [b'^', rest @ ..] = pattern {
        anchor |= 1;
        pattern = rest;
    }
    if let [rest @ .., b'$'] = pattern {
        anchor |= 2;
        pattern = rest;
    }
    if pattern.is_empty() || pattern.len() > 32 {
        return None;
    }
    let mut lit = [0u8; 32];
    for (i, &b) in pattern.iter().enumerate() {
        if !(0x20..0x80).contains(&b) || b"\\^$.[]*+?{}|()".contains(&b) {
            return None;
        }
        lit[i] = b;
    }
    Some((lit, pattern.len() as u8, anchor))
}

pub fn make_xlat(icase: bool, trans: Option<&[u8; 256]>) -> [u8; 256] {
    let mut t = [0u8; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut c = i as u8;
        if let Some(tr) = trans {
            c = tr[i];
        }
        if icase {
            c = charset::to_upper(c);
        }
        *slot = c;
    }
    t
}

pub fn compile(pattern: &[u8], syntax: u64, trans: Option<&[u8; 256]>) -> Result<Compiled, i32> {
    let parsed = parse::parse(pattern, syntax, trans)?;
    let nfa = nfa::build(parsed, syntax)?;
    let mut fm = [0u8; 256];
    let mut cbn = false;
    nfa.fastmap(syntax & RE_ICASE != 0, &mut fm, &mut cbn);
    let xlat = make_xlat(syntax & RE_ICASE != 0 && nfa.mb == charset::Mb::None, trans);
    let (lit, lit_len, lit_anchor) = plain_literal(pattern, syntax, nfa.mb).unwrap_or(([0; 32], 0, 0));
    Ok(Compiled { magic: MAGIC, nfa, fastmap: fm, can_be_null: cbn, xlat, lit, lit_len, lit_anchor })
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    c: &Compiled,
    xlat: &[u8; 256],
    newline_anchor: bool,
    text: &[u8],
    start: isize,
    last_start: isize,
    stop: usize,
    eflags: i32,
    nmatch: usize,
    pmatch: &mut [Reg],
    fastmap: Option<&[u8; 256]>,
    fm_trans: Option<&[u8; 256]>,
) -> i32 {
    if c.lit_len != 0
        && last_start == stop as isize
        && fm_trans.is_none()
        && core::ptr::eq(xlat, &c.xlat)
        && start >= 0
        && start as usize <= stop
        && stop <= text.len()
        && (c.lit_anchor == 0 || (start == 0 && !newline_anchor && eflags & (REG_NOTBOL | REG_NOTEOL) == 0))
    {
        let hay = &text[start as usize..stop];
        let lit = &c.lit[..c.lit_len as usize];
        let at: usize = match c.lit_anchor {
            0 => {
                let at = unsafe { rusty_libc_mem::memmem(hay.as_ptr().cast(), hay.len(), lit.as_ptr().cast(), lit.len()) };
                if at.is_null() { usize::MAX } else { at as usize - hay.as_ptr() as usize }
            }
            1 => if hay.starts_with(lit) { 0 } else { usize::MAX },
            2 => if hay.ends_with(lit) { hay.len() - lit.len() } else { usize::MAX },
            _ => if hay == lit { 0 } else { usize::MAX },
        };
        if at == usize::MAX {
            return REG_NOMATCH;
        }
        if let Some((first, rest)) = pmatch.split_first_mut() {
            let so = (start as usize + at) as i32;
            *first = Reg { so, eo: so + lit.len() as i32 };
            for r in rest {
                *r = exec::UNSET;
            }
        }
        return REG_NOERROR;
    }
    let env = Env {
        nfa: &c.nfa,
        text,
        xlat,
        xlat_fixed: core::ptr::eq(xlat, &c.xlat),
        fastmap,
        fm_trans,
        stop,
        not_bol: eflags & REG_NOTBOL != 0,
        not_eol: eflags & REG_NOTEOL != 0,
        newline_anchor,
        starts: Env::char_starts(&c.nfa, text),
    };
    exec::search_internal(&env, start, last_start, nmatch, pmatch)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error(pub i32);

impl Error {
    pub fn message(&self) -> &'static str {
        match error_message(self.0) {
            Some(m) => core::str::from_utf8(m).unwrap_or("?"),
            None => "?",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

pub struct Regex {
    c: Compiled,
    xlat: [u8; 256],
    newline_anchor: bool,
    no_sub: bool,
}

impl Regex {
    pub fn new(pattern: &[u8], cflags: i32) -> Result<Regex, Error> {
        let mut syntax = if cflags & REG_EXTENDED != 0 { RE_SYNTAX_POSIX_EXTENDED } else { RE_SYNTAX_POSIX_BASIC };
        if cflags & REG_ICASE != 0 {
            syntax |= RE_ICASE;
        }
        let mut newline_anchor = false;
        if cflags & REG_NEWLINE != 0 {
            syntax &= !RE_DOT_NEWLINE;
            syntax |= RE_HAT_LISTS_NOT_NEWLINE;
            newline_anchor = true;
        }
        let mut r = Regex::with_syntax(pattern, syntax, newline_anchor).map_err(|e| if e.0 == REG_ERPAREN { Error(REG_EPAREN) } else { e })?;
        r.no_sub = cflags & REG_NOSUB != 0;
        Ok(r)
    }

    pub fn with_syntax(pattern: &[u8], syntax: u64, newline_anchor: bool) -> Result<Regex, Error> {
        let c = compile(pattern, syntax, None).map_err(Error)?;
        let xlat = c.xlat;
        Ok(Regex { c, xlat, newline_anchor, no_sub: syntax & RE_NO_SUB != 0 })
    }

    pub fn group_count(&self) -> usize {
        self.c.nfa.nsub as usize
    }

    pub fn exec(&self, text: &[u8], start: usize, eflags: i32, out: &mut [Reg]) -> Result<bool, Error> {
        let nmatch = if self.no_sub { 0 } else { out.len() };
        let fm = if !self.c.can_be_null && start != text.len() { Some(&self.c.fastmap) } else { None };
        match run(&self.c, &self.xlat, self.newline_anchor, text, start as isize, text.len() as isize, text.len(), eflags, nmatch, out, fm, None) {
            REG_NOERROR => Ok(true),
            REG_NOMATCH => Ok(false),
            e => Err(Error(e)),
        }
    }

    pub fn is_match(&self, text: &[u8]) -> bool {
        self.exec(text, 0, 0, &mut []).unwrap_or(false)
    }

    pub fn find(&self, text: &[u8]) -> Option<Span> {
        self.find_at(text, 0)
    }

    pub fn find_at(&self, text: &[u8], start: usize) -> Option<Span> {
        let mut m = [exec::UNSET];
        match self.exec(text, start, 0, &mut m) {
            Ok(true) => Some(Span { start: m[0].so as usize, end: m[0].eo as usize }),
            _ => None,
        }
    }

    pub fn captures(&self, text: &[u8], caps: &mut [Option<Span>]) -> bool {
        let mut regs: V<Reg> = V::from_elem(exec::UNSET, caps.len());
        if regs.oom {
            return false;
        }
        let ok = self.exec(text, 0, 0, &mut regs).unwrap_or(false);
        for (c, r) in caps.iter_mut().zip(regs.iter()) {
            *c = if ok && r.so >= 0 { Some(Span { start: r.so as usize, end: r.eo as usize }) } else { None };
        }
        ok
    }
}

impl core::fmt::Debug for Regex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Regex {{ groups: {} }}", self.group_count())
    }
}
