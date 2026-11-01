//! Drift checks between the header tables and the library crates.
//!
//! The header data holds constants as tables (the crates are no_std and must not be pulled into this host tool).
//! To keep header and library from drifting, every header constant whose name is also a `const` of a crate is
//! compared with the crate's value (the crate sources are parsed with syn and the constant expressions
//! evaluated). The same module reports, per header, how many constants were checked against a crate, how many
//! have no crate counterpart (table only; the C/Rust layout and constant tests under tests/ compare those with
//! glibc), and how many are expressions this checker cannot evaluate.

use crate::model::{Header, Item, V};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use syn::{BinOp, Expr, Lit, UnOp};

/// Every constant source: the hand-described headers plus the C text of the cbindgen-made headers (as pseudo
/// headers named after the header the config makes).
pub fn sources() -> &'static [&'static Header] {
    static S: std::sync::OnceLock<Vec<&'static Header>> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let mut v: Vec<&'static Header> = crate::hdr::ALL.to_vec();
        let specs = crate::specs::build_specs();
        for (name, t) in crate::hdr_cb::ALL {
            let hdr = specs.iter().find(|s| s.config == *name).map(|s| format!("{}.h", s.name)).unwrap_or_else(|| format!("{name}.h"));
            let mut items: Vec<Item> = Vec::new();
            for x in [&t.header, &t.after_includes, &t.trailer].into_iter().flatten() {
                items.extend_from_slice(x.0);
            }
            let path: &'static str = Box::leak(hdr.into_boxed_str());
            let items: &'static [Item] = Box::leak(items.into_boxed_slice());
            v.push(Box::leak(Box::new(Header { path, items })));
        }
        v
    })
}

pub type CrateConsts = BTreeMap<String, Vec<(String, i128)>>; // name -> [(crate, value)]

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut ents: Vec<_> = rd.map(|e| e.unwrap().path()).collect();
    ents.sort();
    for p in ents {
        if p.is_dir() {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            if n == "target" || n.starts_with('.') {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn parse_int_lit(s: &str) -> Option<i128> {
    let s: String = s.chars().filter(|c| *c != '_').collect();
    let (digits, radix) = if let Some(r) = s.strip_prefix("0x") {
        (r.to_string(), 16)
    } else if let Some(r) = s.strip_prefix("0o") {
        (r.to_string(), 8)
    } else if let Some(r) = s.strip_prefix("0b") {
        (r.to_string(), 2)
    } else {
        (s.clone(), 10)
    };
    let mut d = digits.clone();
    for suf in ["u128", "i128", "usize", "isize", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8"] {
        if let Some(x) = d.strip_suffix(suf) {
            d = x.to_string();
            break;
        }
    }
    i128::from_str_radix(&d, radix).ok()
}

fn cast_to(v: i128, ty: &str) -> Option<i128> {
    let (bits, signed) = match ty {
        "u8" => (8, false), "u16" | "c_ushort" => (16, false), "u32" | "c_uint" => (32, false),
        "u64" | "usize" | "c_ulong" | "c_ulonglong" => (64, false),
        "i8" | "c_char" | "c_schar" => (8, true), "i16" | "c_short" => (16, true), "i32" | "c_int" => (32, true),
        "i64" | "isize" | "c_long" | "c_longlong" => (64, true),
        _ => return None,
    };
    let m = (1i128 << bits) - 1;
    let u = v & m;
    Some(if signed && u >> (bits - 1) == 1 { u - (1i128 << bits) } else { u })
}

fn eval(e: &Expr, env: &dyn Fn(&str) -> Option<i128>) -> Option<i128> {
    match e {
        Expr::Lit(l) => match &l.lit {
            Lit::Int(i) => parse_int_lit(&i.to_string()),
            Lit::Byte(b) => Some(b.value() as i128),
            Lit::Char(c) => Some(c.value() as i128),
            Lit::Bool(b) => Some(b.value as i128),
            _ => None,
        },
        Expr::Paren(p) => eval(&p.expr, env),
        Expr::Group(g) => eval(&g.expr, env),
        Expr::Unary(u) => {
            let v = eval(&u.expr, env)?;
            match u.op {
                UnOp::Neg(_) => Some(-v),
                UnOp::Not(_) => Some(!v),
                _ => None,
            }
        }
        Expr::Cast(c) => {
            let v = eval(&c.expr, env)?;
            if let syn::Type::Path(tp) = &*c.ty {
                cast_to(v, &tp.path.segments.last()?.ident.to_string())
            } else {
                None
            }
        }
        Expr::Binary(b) => {
            let l = eval(&b.left, env)?;
            let r = eval(&b.right, env)?;
            match b.op {
                BinOp::Add(_) => l.checked_add(r),
                BinOp::Sub(_) => l.checked_sub(r),
                BinOp::Mul(_) => l.checked_mul(r),
                BinOp::Div(_) => l.checked_div(r),
                BinOp::BitOr(_) => Some(l | r),
                BinOp::BitAnd(_) => Some(l & r),
                BinOp::BitXor(_) => Some(l ^ r),
                BinOp::Shl(_) => Some(l << (r as u32)),
                BinOp::Shr(_) => Some(l >> (r as u32)),
                _ => None,
            }
        }
        Expr::Path(p) => {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if segs.len() == 2 && segs[1] == "MAX" {
                return cast_to(-1, &segs[0]).map(|m| if m < 0 { -1 } else { m }).and_then(|_| match segs[0].as_str() {
                    "u8" => Some(255), "u16" => Some(65535), "u32" => Some(u32::MAX as i128), "u64" | "usize" => Some(u64::MAX as i128),
                    "i32" => Some(i32::MAX as i128), "i64" | "isize" => Some(i64::MAX as i128), _ => None,
                });
            }
            env(segs.last()?)
        }
        _ => None,
    }
}

/// Every integer `const` of the crates (module level or inside inline modules), by name.
pub fn crate_consts(root: &Path) -> CrateConsts {
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    // pass 1: collect the const items with their expressions
    struct C {
        krate: String,
        name: String,
        expr: Expr,
    }
    let mut all: Vec<C> = Vec::new();
    fn walk(items: &[syn::Item], krate: &str, all: &mut Vec<C>) {
        for it in items {
            match it {
                syn::Item::Const(c) => all.push(C { krate: krate.to_string(), name: c.ident.to_string(), expr: (*c.expr).clone() }),
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        walk(items, krate, all);
                    }
                }
                _ => {}
            }
        }
    }
    for f in files {
        let rel = f.strip_prefix(root.join("crates")).unwrap().to_string_lossy().to_string();
        let krate = rel.split('/').next().unwrap().to_string();
        let Ok(text) = fs::read_to_string(&f) else { continue };
        let Ok(file) = syn::parse_file(&text) else { continue };
        walk(&file.items, &krate, &mut all);
    }
    // pass 2: evaluate, iterating so that constants defined from other constants resolve
    let mut known: BTreeMap<String, Vec<(String, i128)>> = BTreeMap::new();
    for _ in 0..4 {
        let snapshot = known.clone();
        for c in &all {
            let env = |n: &str| -> Option<i128> {
                // prefer a definition from the same crate
                let v = snapshot.get(n)?;
                v.iter().find(|(k, _)| *k == c.krate).or(v.first()).map(|x| x.1)
            };
            if let Some(v) = eval(&c.expr, &env) {
                let e = known.entry(c.name.clone()).or_default();
                if !e.iter().any(|(k, x)| *k == c.krate && *x == v) {
                    e.push((c.krate.clone(), v));
                }
            }
        }
    }
    known
}

// ---- a small evaluator for the C expressions of the header tables

struct CParser<'a> {
    s: &'a [u8],
    i: usize,
    env: &'a dyn Fn(&str) -> Option<i128>,
}

impl<'a> CParser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn eat(&mut self, t: &str) -> bool {
        self.ws();
        if self.s[self.i..].starts_with(t.as_bytes()) {
            self.i += t.len();
            true
        } else {
            false
        }
    }
    fn primary(&mut self) -> Option<i128> {
        self.ws();
        if self.eat("(") {
            // a cast like (unsigned)x is not supported; a parenthesised expression is
            let v = self.or()?;
            if !self.eat(")") {
                return None;
            }
            return Some(v);
        }
        if self.eat("-") {
            return self.primary().map(|v| -v);
        }
        if self.eat("~") {
            return self.primary().map(|v| !v);
        }
        let start = self.i;
        while self.i < self.s.len() && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_') {
            self.i += 1;
        }
        let tok = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if tok.is_empty() {
            return None;
        }
        if tok.as_bytes()[0].is_ascii_digit() {
            let t = tok.trim_end_matches(['u', 'U', 'l', 'L']);
            return if let Some(h) = t.strip_prefix("0x").or(t.strip_prefix("0X")) {
                i128::from_str_radix(h, 16).ok()
            } else if t.len() > 1 && t.starts_with('0') {
                i128::from_str_radix(&t[1..], 8).ok()
            } else {
                t.parse().ok()
            };
        }
        (self.env)(tok)
    }
    fn shift(&mut self) -> Option<i128> {
        let mut v = self.add()?;
        loop {
            if self.eat("<<") {
                v <<= self.add()? as u32;
            } else if self.eat(">>") {
                v >>= self.add()? as u32;
            } else {
                return Some(v);
            }
        }
    }
    fn add(&mut self) -> Option<i128> {
        let mut v = self.mul()?;
        loop {
            self.ws();
            if self.eat("+") {
                v += self.mul()?;
            } else if self.s.get(self.i) == Some(&b'-') {
                self.i += 1;
                v -= self.mul()?;
            } else {
                return Some(v);
            }
        }
    }
    fn mul(&mut self) -> Option<i128> {
        let mut v = self.primary()?;
        loop {
            if self.eat("*") {
                v *= self.primary()?;
            } else {
                return Some(v);
            }
        }
    }
    fn and(&mut self) -> Option<i128> {
        let mut v = self.shift()?;
        while self.eat("&") {
            v &= self.shift()?;
        }
        Some(v)
    }
    fn or(&mut self) -> Option<i128> {
        let mut v = self.and()?;
        loop {
            self.ws();
            if self.s.get(self.i) == Some(&b'|') && self.s.get(self.i + 1) != Some(&b'|') {
                self.i += 1;
                v |= self.and()?;
            } else {
                return Some(v);
            }
        }
    }
}

fn eval_c(text: &str, env: &dyn Fn(&str) -> Option<i128>) -> Option<i128> {
    let t = text.split("/*").next().unwrap().trim();
    let mut p = CParser { s: t.as_bytes(), i: 0, env };
    let v = p.or()?;
    p.ws();
    if p.i == t.len() { Some(v) } else { None }
}

/// Same name, unrelated meaning in a crate: (header, constant, why). Everything else with a crate counterpart must be equal.
/// langinfo.h is compared as (category << 16 | index) against the crate's bare item index; a crate value that is
/// negative (a u32 spelled as i32) is compared modulo 2^32.
const UNRELATED: &[(&str, &str, &str)] = &[
    ("arpa/telnet.h", "ABORT", "telnet command code; the crate constant is a signal number"),
    ("arpa/telnet.h", "SB", "telnet subnegotiation command; the crate constant is an iconv state"),
    ("sys/param.h", "MAXSYMLINKS", "glibc's sys/param.h value (20); the stdlib crate's constant is realpath's own loop limit"),
];

// ---- the report

#[derive(Default)]
pub struct HeaderStat {
    pub checked: usize,
    pub mismatched: Vec<String>,
    pub table_only: usize,
    pub unevaluated: usize,
}

fn collect_consts(items: &'static [Item], out: &mut Vec<(&'static str, V)>) {
    for it in items {
        match it {
            Item::Consts(cs) | Item::ConstsFlat(cs) => out.extend(cs.iter().copied()),
            Item::Gate(bs, _) => {
                for b in bs.iter() {
                    collect_consts(b.items, out);
                }
            }
            Item::Guard { items, .. } => collect_consts(items, out),
            _ => {}
        }
    }
}

pub fn check_headers(all: &'static [&'static Header], cc: &CrateConsts) -> BTreeMap<&'static str, HeaderStat> {
    // the values of the header constants, to resolve names that refer to other header constants
    let mut table: BTreeMap<&str, Vec<(&str, V)>> = BTreeMap::new();
    let mut per: Vec<(&'static str, Vec<(&'static str, V)>)> = Vec::new();
    for h in all {
        let mut v = Vec::new();
        collect_consts(h.items, &mut v);
        for (n, val) in &v {
            table.entry(n).or_default().push((h.path, *val));
        }
        per.push((h.path, v));
    }
    fn int_of(v: &V, env: &dyn Fn(&str) -> Option<i128>) -> Option<i128> {
        match v {
            V::Dec(n) => Some(*n as i128),
            V::Hex(n) => Some(*n as i128),
            V::Txt(t) | V::Sp(t) => eval_c(t.trim(), env),
        }
    }
    let env0 = |_: &str| -> Option<i128> { None };
    // a name defined more than once (redefined under a feature test) is ambiguous for expressions that use it
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, v) in &per {
        for (n, _) in v {
            *count.entry(n).or_default() += 1;
        }
    }
    let mut simple: BTreeMap<&str, i128> = BTreeMap::new();
    for (_, v) in &per {
        for (n, val) in v {
            if count[n] == 1 {
                if let Some(x) = int_of(val, &env0) {
                    simple.insert(n, x);
                }
            }
        }
    }
    let env = |n: &str| simple.get(n).copied();
    let mut out = BTreeMap::new();
    for (path, v) in &per {
        let mut st = HeaderStat::default();
        for (n, val) in v {
            if UNRELATED.iter().any(|(h, nm, _)| h == path && nm == n) {
                st.table_only += 1;
                continue;
            }
            let Some(hv) = int_of(val, &env) else {
                st.unevaluated += 1;
                continue;
            };
            match cc.get(*n) {
                Some(defs) => {
                    let enc = |x: i128| if *path == "langinfo.h" { x | (hv & !0xffff) } else { x };
                    if defs.iter().any(|(_, x)| enc(*x) == hv || (*x < 0 && (*x & 0xffff_ffff) == hv)) {
                        st.checked += 1;
                    } else {
                        st.mismatched.push(format!("{n}: header {hv}, crates {:?}", defs));
                    }
                }
                None => st.table_only += 1,
            }
        }
        out.insert(*path, st);
    }
    out
}

pub fn print_report(stats: &BTreeMap<&'static str, HeaderStat>) {
    let (mut c, mut m, mut t, mut u) = (0, 0, 0, 0);
    println!("{:34} {:>8} {:>9} {:>11} {:>6}", "header", "crate-eq", "mismatch", "table-only", "expr");
    for (h, s) in stats {
        if s.checked + s.mismatched.len() + s.table_only + s.unevaluated == 0 {
            continue;
        }
        println!("{:34} {:>8} {:>9} {:>11} {:>6}", h, s.checked, s.mismatched.len(), s.table_only, s.unevaluated);
        for x in &s.mismatched {
            println!("    MISMATCH {x}");
        }
        c += s.checked;
        m += s.mismatched.len();
        t += s.table_only;
        u += s.unevaluated;
    }
    println!("total: {c} constants equal to a crate const, {m} mismatches, {t} table-only, {u} not evaluated");
}

/// Integer constants of one header (unique definitions only), with their evaluated values.
fn header_int_consts(h: &'static Header, env: &dyn Fn(&str) -> Option<i128>) -> Vec<(&'static str, i128)> {
    let mut v = Vec::new();
    collect_consts(h.items, &mut v);
    let mut out: Vec<(&'static str, i128)> = Vec::new();
    for (n, val) in v.iter().copied() {
        if v.iter().filter(|(m, _)| *m == n).count() > 1 {
            continue; // redefined under a feature test: the value depends on the mode
        }
        let x = match val {
            V::Dec(n) => Some(n as i128),
            V::Hex(n) => Some(n as i128),
            V::Txt(t) | V::Sp(t) => eval_c(t.trim(), env),
        };
        if let Some(x) = x {
            if !out.iter().any(|(m, _)| *m == n) {
                out.push((n, x));
            }
        }
    }
    out
}

#[derive(Default)]
pub struct GlibcStat {
    pub equal: usize,
    pub differ: Vec<String>,
    pub undefined_in_glibc: usize,
    pub header_missing: bool,
    pub compile_failed: bool,
}

/// Compare every integer constant of every header table with the value the host's glibc headers give the same
/// name (the host runs glibc; the tables were first taken from its headers). Needs gcc.
pub fn check_against_glibc(all: &'static [&'static Header], scratch: &Path) -> BTreeMap<&'static str, GlibcStat> {
    fs::create_dir_all(scratch).unwrap();
    let mut count: BTreeMap<&str, usize> = BTreeMap::new();
    let mut per: Vec<(&'static Header, Vec<(&'static str, V)>)> = Vec::new();
    for h in all {
        let mut v = Vec::new();
        collect_consts(h.items, &mut v);
        for (n, _) in &v {
            *count.entry(n).or_default() += 1;
        }
        per.push((h, v));
    }
    let mut simple: BTreeMap<&str, i128> = BTreeMap::new();
    for (_, v) in &per {
        for (n, val) in v {
            if count[n] == 1 {
                let x = match val {
                    V::Dec(d) => Some(*d as i128),
                    V::Hex(d) => Some(*d as i128),
                    V::Txt(t) | V::Sp(t) => eval_c(t.trim(), &|_| None),
                };
                if let Some(x) = x {
                    simple.insert(n, x);
                }
            }
        }
    }
    let env = |n: &str| simple.get(n).copied();
    let mut out = BTreeMap::new();
    for (h, _) in &per {
        let mut st = GlibcStat::default();
        let consts = header_int_consts(h, &env);
        if consts.is_empty() {
            continue;
        }
        let run = |names: &[&str]| -> Option<String> {
            let mut c = String::from("#define _GNU_SOURCE 1\n#include <stdio.h>\n");
            c.push_str(&format!("#if __has_include(<{0}>)\n#include <{0}>\n#else\n#define HDR_MISSING 1\n#endif\n", h.path));
            c.push_str("int main(void) {\n#ifdef HDR_MISSING\n puts(\"MISSING\");\n#else\n");
            for n in names {
                c.push_str(&format!("#ifdef {n}\n printf(\"{n} %lld\\n\", (long long)({n}));\n#else\n printf(\"{n} UNDEF\\n\");\n#endif\n"));
            }
            c.push_str("#endif\n return 0;\n}\n");
            let src = scratch.join("g.c");
            let exe = scratch.join("g.out");
            fs::write(&src, c).unwrap();
            let ok = std::process::Command::new("gcc").args(["-w", "-o"]).arg(&exe).arg(&src).output().map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                return None;
            }
            let o = std::process::Command::new("timeout").args(["--kill-after=5", "20"]).arg(&exe).output().unwrap();
            Some(String::from_utf8_lossy(&o.stdout).to_string())
        };
        let names: Vec<&str> = consts.iter().map(|(n, _)| *n).collect();
        let text = match run(&names) {
            Some(t) => t,
            None => {
                // some constant is not an integer expression in glibc: try them one by one
                let mut t = String::new();
                let mut skipped = 0;
                for n in &names {
                    match run(&[n]) {
                        Some(x) => t.push_str(&x),
                        None => skipped += 1,
                    }
                }
                if skipped == names.len() {
                    st.compile_failed = true;
                    out.insert(h.path, st);
                    continue;
                }
                t
            }
        };
        if text.trim() == "MISSING" {
            st.header_missing = true;
            out.insert(h.path, st);
            continue;
        }
        for line in text.lines() {
            if line == "MISSING" { continue; }
            let (n, v) = line.split_once(' ').unwrap();
            let mine = consts.iter().find(|(m, _)| *m == n).unwrap().1;
            if v == "UNDEF" {
                st.undefined_in_glibc += 1;
            } else {
                let gv: i128 = v.parse().unwrap();
                if gv == mine || ((gv & 0xffff_ffff) == (mine & 0xffff_ffff) && (mine < 0 || gv < 0 || mine > i32::MAX as i128)) {
                    st.equal += 1;
                } else {
                    st.differ.push(format!("{n}: header {mine}, glibc {gv}"));
                }
            }
        }
        out.insert(h.path, st);
    }
    out
}

pub fn print_glibc_report(stats: &BTreeMap<&'static str, GlibcStat>) {
    let (mut e, mut d, mut u, mut m, mut f) = (0, 0, 0, 0, 0);
    for (h, s) in stats {
        if s.header_missing {
            m += 1;
            continue;
        }
        if s.compile_failed {
            f += 1;
            println!("{h}: could not be compiled against the host's glibc headers (not checked)");
            continue;
        }
        println!("{:34} equal {:5}  differ {:3}  not-defined-by-glibc {:4}", h, s.equal, s.differ.len(), s.undefined_in_glibc);
        for x in &s.differ {
            println!("    DIFFER {x}");
        }
        e += s.equal;
        d += s.differ.len();
        u += s.undefined_in_glibc;
    }
    println!("total: {e} equal to glibc, {d} differ, {u} not defined by the host glibc, {m} headers absent on the host, {f} not compilable");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Header constants that also exist as crate constants must have the same value.
    #[test]
    fn header_constants_match_crates() {
        let cc = crate_consts(&root());
        assert!(cc.len() > 1000, "crate constants not found ({})", cc.len());
        let stats = check_headers(sources(), &cc);
        let bad: Vec<String> = stats.iter().flat_map(|(h, s)| s.mismatched.iter().map(move |m| format!("{h}: {m}"))).collect();
        assert!(bad.is_empty(), "header/crate constant drift:\n{}", bad.join("\n"));
        let checked: usize = stats.values().map(|s| s.checked).sum();
        assert!(checked > 100, "only {checked} constants were compared");
    }
}
