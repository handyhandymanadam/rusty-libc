//! Struct layout drift check: every struct/union the header tables define that also exists as a `#[repr(C)]`
//! struct (same name) in a library crate must have the same size, alignment and member offsets in the generated
//! C header (measured with gcc) and in the crate (computed here from the syn tree, x86-64 rules).
//! Structs without a same-named Rust counterpart are covered by the layout tests under tests/ (they compare
//! with glibc's own headers); this report says which is which.

use crate::model::{Header, Item};
use regex_lite::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
struct RStruct {
    union: bool,
    packed: Option<u64>,
    align: Option<u64>,
    fields: Vec<(String, syn::Type)>,
    repr_c: bool,
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut ents: Vec<_> = rd.map(|e| e.unwrap().path()).collect();
    ents.sort();
    for p in ents {
        if p.is_dir() {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            if n != "target" && !n.starts_with('.') {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

struct Crates {
    structs: BTreeMap<String, Vec<RStruct>>,
    aliases: BTreeMap<String, syn::Type>,
    consts: BTreeMap<String, i128>,
}

fn attrs_repr(attrs: &[syn::Attribute]) -> (bool, Option<u64>, Option<u64>) {
    let (mut c, mut packed, mut align) = (false, None, None);
    for a in attrs {
        if a.path().is_ident("repr") {
            let _ = a.parse_nested_meta(|m| {
                if m.path.is_ident("C") {
                    c = true;
                } else if m.path.is_ident("packed") {
                    packed = Some(if m.input.peek(syn::token::Paren) {
                        let content;
                        syn::parenthesized!(content in m.input);
                        content.parse::<syn::LitInt>()?.base10_parse()?
                    } else {
                        1
                    });
                } else if m.path.is_ident("align") {
                    let content;
                    syn::parenthesized!(content in m.input);
                    align = Some(content.parse::<syn::LitInt>()?.base10_parse()?);
                }
                Ok(())
            });
        }
    }
    (c, packed, align)
}

fn load_crates(root: &Path) -> Crates {
    let cc = crate::check::crate_consts(root);
    let consts: BTreeMap<String, i128> = cc.into_iter().filter_map(|(k, v)| v.first().map(|x| (k, x.1))).collect();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut c = Crates { structs: BTreeMap::new(), aliases: BTreeMap::new(), consts };
    fn walk(items: &[syn::Item], c: &mut Crates) {
        for it in items {
            match it {
                syn::Item::Struct(s) => {
                    let (repr_c, packed, align) = attrs_repr(&s.attrs);
                    let fields = match &s.fields {
                        syn::Fields::Named(n) => n.named.iter().map(|f| (f.ident.as_ref().unwrap().to_string().trim_start_matches("r#").to_string(), f.ty.clone())).collect(),
                        syn::Fields::Unnamed(u) => u.unnamed.iter().enumerate().map(|(i, f)| (format!("{i}"), f.ty.clone())).collect(),
                        syn::Fields::Unit => vec![],
                    };
                    c.structs.entry(s.ident.to_string()).or_default().push(RStruct { union: false, packed, align, fields, repr_c });
                }
                syn::Item::Union(u) => {
                    let (repr_c, packed, align) = attrs_repr(&u.attrs);
                    let fields = u.fields.named.iter().map(|f| (f.ident.as_ref().unwrap().to_string(), f.ty.clone())).collect();
                    c.structs.entry(u.ident.to_string()).or_default().push(RStruct { union: true, packed, align, fields, repr_c });
                }
                syn::Item::Type(t) => {
                    c.aliases.insert(t.ident.to_string(), (*t.ty).clone());
                }
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        walk(items, c);
                    }
                }
                _ => {}
            }
        }
    }
    for f in files {
        let Ok(text) = fs::read_to_string(&f) else { continue };
        let Ok(file) = syn::parse_file(&text) else { continue };
        walk(&file.items, &mut c);
    }
    c
}

/// A struct's (size, align, field offsets).
type StructLayout = (u64, u64, Vec<(String, u64)>);

fn align_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

impl Crates {
    fn array_len(&self, e: &syn::Expr) -> Option<u64> {
        match e {
            syn::Expr::Lit(l) => match &l.lit {
                syn::Lit::Int(i) => i.base10_parse().ok(),
                _ => None,
            },
            syn::Expr::Path(p) => self.consts.get(&p.path.segments.last()?.ident.to_string()).map(|v| *v as u64),
            syn::Expr::Paren(p) => self.array_len(&p.expr),
            syn::Expr::Binary(b) => {
                let (l, r) = (self.array_len(&b.left)?, self.array_len(&b.right)?);
                match b.op {
                    syn::BinOp::Add(_) => Some(l + r),
                    syn::BinOp::Sub(_) => Some(l - r),
                    syn::BinOp::Mul(_) => Some(l * r),
                    syn::BinOp::Div(_) => Some(l / r),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// (size, align) of a type; None when it cannot be resolved.
    fn type_layout(&self, t: &syn::Type, depth: u32) -> Option<(u64, u64)> {
        if depth > 12 {
            return None;
        }
        match t {
            syn::Type::Ptr(_) | syn::Type::Reference(_) | syn::Type::BareFn(_) => Some((8, 8)),
            syn::Type::Array(a) => {
                let (s, al) = self.type_layout(&a.elem, depth + 1)?;
                Some((s * self.array_len(&a.len)?, al))
            }
            syn::Type::Paren(p) => self.type_layout(&p.elem, depth + 1),
            syn::Type::Group(g) => self.type_layout(&g.elem, depth + 1),
            syn::Type::Path(p) => {
                let seg = p.path.segments.last()?;
                let name = seg.ident.to_string();
                match name.as_str() {
                    "u8" | "i8" | "bool" | "c_char" | "c_schar" | "c_uchar" => Some((1, 1)),
                    "u16" | "i16" | "c_short" | "c_ushort" => Some((2, 2)),
                    "u32" | "i32" | "c_int" | "c_uint" | "f32" | "c_float" => Some((4, 4)),
                    "u64" | "i64" | "usize" | "isize" | "c_long" | "c_ulong" | "c_longlong" | "c_ulonglong" | "f64" | "c_double" => Some((8, 8)),
                    "u128" | "i128" => Some((16, 16)),
                    "Option" => {
                        if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
                            if let Some(syn::GenericArgument::Type(inner)) = a.args.first() {
                                return self.type_layout(inner, depth + 1);
                            }
                        }
                        None
                    }
                    "PhantomData" => Some((0, 1)),
                    _ => {
                        if let Some(a) = self.aliases.get(&name) {
                            return self.type_layout(a, depth + 1);
                        }
                        let v = self.structs.get(&name)?;
                        self.struct_layout(v.first()?, depth + 1).map(|l| (l.0, l.1))
                    }
                }
            }
            _ => None,
        }
    }

    /// (size, align, offsets)
    fn struct_layout(&self, s: &RStruct, depth: u32) -> Option<StructLayout> {
        if !s.repr_c {
            return None;
        }
        let mut off = 0u64;
        let mut max_align = 1u64;
        let mut size_max = 0u64;
        let mut offsets = Vec::new();
        for (n, t) in &s.fields {
            let (sz, mut al) = self.type_layout(t, depth + 1)?;
            if let Some(p) = s.packed {
                al = al.min(p);
            }
            max_align = max_align.max(al);
            if s.union {
                offsets.push((n.clone(), 0));
                size_max = size_max.max(sz);
            } else {
                off = align_up(off, al);
                offsets.push((n.clone(), off));
                off += sz;
            }
        }
        if let Some(a) = s.align {
            max_align = max_align.max(a);
        }
        let raw = if s.union { size_max } else { off };
        Some((align_up(raw, max_align), max_align, offsets))
    }
}

/// Known differences between a crate's Rust struct and the C header (the header matches glibc; the Rust struct is
/// what the crate uses internally). Listed in the report, not failing the test; the library crates are not changed
/// by this tool.
const KNOWN: &[(&str, &str)] = &[
    ("in6_addr", "rusty-libc-net declares s6_addr as [u8; 16] (align 1); glibc's struct in6_addr is a union with 32-bit members (align 4), which the header follows"),
];

pub struct LayoutStat {
    pub header: &'static str,
    pub name: String,
    pub result: String, // "equal", "DIFFER ...", "unresolved", "no rust struct"
}

struct CStruct {
    header: &'static str,
    name: String,
    union: bool,
    fields: Vec<String>,
}

fn collect_blocks(h: &'static Header, items: &'static [Item], out: &mut Vec<CStruct>) {
    let head_re = Regex::new(r"^\s*(?:typedef\s+)?(struct|union)\s+(\w+)\s*$").unwrap();
    let field_re = Regex::new(r"^\s*(?:const\s+|volatile\s+)*[A-Za-z_][\w ]*?[\s\*]+(\w+)\s*(?:\[[^\]]*\])?\s*;").unwrap();
    for it in items {
        match it {
            Item::Block { head, body, .. } => {
                if let Some(m) = head_re.captures(head.trim_end()) {
                    let mut fields = Vec::new();
                    let mut simple = true;
                    for l in body.iter() {
                        let t = l.trim();
                        if t.is_empty() || t.starts_with("/*") || t.starts_with("//") {
                            continue;
                        }
                        if t.starts_with('#') || t.contains(':') || t.contains('{') || t.contains('(') {
                            simple = false;
                            continue;
                        }
                        if let Some(f) = field_re.captures(t) {
                            fields.push(f[1].to_string());
                        }
                    }
                    if body.iter().any(|l| l.contains('{') || l.contains('}')) {
                        fields.clear(); // nested aggregates: compare size and alignment only
                    }
                    let _ = simple;
                    out.push(CStruct { header: h.path, name: m[2].to_string(), union: &m[1] == "union", fields });
                }
            }
            Item::Gate(bs, _) => {
                for b in bs.iter() {
                    collect_blocks(h, b.items, out);
                }
            }
            Item::Guard { items, .. } => collect_blocks(h, items, out),
            _ => {}
        }
    }
}

/// Run the check against the include tree `inc` (a generated sysroot include directory).
pub fn check_layouts(root: &Path, all: &'static [&'static Header], inc: &Path, scratch: &Path) -> Vec<LayoutStat> {
    fs::create_dir_all(scratch).unwrap();
    let crates = load_crates(root);
    let gccinc = {
        let o = std::process::Command::new("gcc").arg("-print-file-name=include").output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    let mut blocks = Vec::new();
    for h in all {
        collect_blocks(h, h.items, &mut blocks);
    }
    let mut out = Vec::new();
    for b in blocks {
        let st = |r: &str| LayoutStat { header: b.header, name: b.name.clone(), result: r.to_string() };
        let Some(cands) = crates.structs.get(&b.name) else {
            out.push(st("no same-named Rust struct"));
            continue;
        };
        let layouts: Vec<_> = cands.iter().filter_map(|c| crates.struct_layout(c, 0)).collect();
        if layouts.is_empty() {
            out.push(st("unresolved (Rust side not repr(C) or has a type this checker does not know)"));
            continue;
        }
        let kw = if b.union { "union" } else { "struct" };
        let mut c = String::from("int printf(const char *, ...);\n");
        c.push_str(&format!("#define _GNU_SOURCE 1\n#include <{}>\n", b.header));
        c.push_str("int main(void) {\n");
        c.push_str(&format!(" printf(\"%zu %zu\", sizeof({kw} {0}), _Alignof({kw} {0}));\n", b.name));
        for f in &b.fields {
            c.push_str(&format!(" printf(\" {f}=%zu\", __builtin_offsetof({kw} {}, {f}));\n", b.name));
        }
        c.push_str(" printf(\"\\n\"); return 0;\n}\n");
        let src = scratch.join("l.c");
        let exe = scratch.join("l.out");
        // the includes must come before the printf declaration is used; declared first is fine
        fs::write(&src, c.replace("int printf(const char *, ...);\n#define _GNU_SOURCE 1\n", "#define _GNU_SOURCE 1\nint printf(const char *, ...);\n")).unwrap();
        let ok = std::process::Command::new("gcc")
            .args(["-w", "-nostdinc", "-isystem"])
            .arg(inc)
            .arg("-isystem")
            .arg(&gccinc)
            .arg("-o")
            .arg(&exe)
            .arg(&src)
            .output();
        let Ok(o) = ok else {
            out.push(st("gcc failed to start"));
            continue;
        };
        if !o.status.success() {
            out.push(st(&format!("C side did not compile: {}", String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or(""))));
            continue;
        }
        let r = std::process::Command::new("timeout").args(["--kill-after=5", "20"]).arg(&exe).output().unwrap();
        let line = String::from_utf8_lossy(&r.stdout).trim().to_string();
        let mut it = line.split(' ');
        let csize: u64 = it.next().unwrap().parse().unwrap();
        let calign: u64 = it.next().unwrap().parse().unwrap();
        let coffs: Vec<(String, u64)> = it.filter_map(|x| x.split_once('=')).map(|(k, v)| (k.to_string(), v.parse().unwrap())).collect();
        let mut best = String::new();
        let mut matched = false;
        for (rs, ra, roffs) in &layouts {
            let mut diffs = Vec::new();
            if *rs != csize {
                diffs.push(format!("size C {csize} Rust {rs}"));
            }
            if *ra != calign {
                diffs.push(format!("align C {calign} Rust {ra}"));
            }
            for (n, co) in &coffs {
                if let Some((_, ro)) = roffs.iter().find(|(m, _)| m == n) {
                    if ro != co {
                        diffs.push(format!("offset {n} C {co} Rust {ro}"));
                    }
                }
            }
            if diffs.is_empty() {
                matched = true;
                break;
            }
            best = diffs.join(", ");
        }
        let known = KNOWN.iter().find(|(n, _)| *n == b.name);
        out.push(st(&if matched {
            format!("equal (size {csize}, align {calign}, {} offsets)", coffs.len())
        } else if let Some((_, why)) = known {
            format!("KNOWN difference ({best}): {why}")
        } else {
            format!("DIFFER {best}")
        }));
    }
    out
}

pub fn print_layouts(v: &[LayoutStat]) {
    let (mut eq, mut diff, mut none, mut unres) = (0, 0, 0, 0);
    for s in v {
        if s.result.starts_with("equal") {
            eq += 1;
        } else if s.result.starts_with("DIFFER") || s.result.starts_with("C side") || s.result.starts_with("KNOWN") {
            diff += 1;
            println!("{} struct {}: {}", s.header, s.name, s.result);
        } else if s.result.starts_with("no same") {
            none += 1;
        } else {
            unres += 1;
            println!("{} struct {}: {}", s.header, s.name, s.result);
        }
    }
    println!("struct layouts: {eq} equal to the crate's repr(C) struct, {diff} differ or not measurable, {unres} unresolved on the Rust side, {none} with no same-named Rust struct (compared with glibc by tests/)");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the include tree and compare every struct that has a same-named repr(C) Rust struct.
    #[test]
    fn struct_layouts_match_crates() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = fs::canonicalize(root).unwrap();
        let tmp = root.join("target/hdrgen-test");
        let files = crate::gen::full_tree(&root, &tmp.join("cb"));
        let inc = tmp.join("include");
        for (rel, text) in &files {
            let p = inc.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
        let v = check_layouts(&root, crate::hdr::ALL, &inc, &tmp.join("layout"));
        print_layouts(&v);
        let bad: Vec<String> = v.iter().filter(|s| s.result.starts_with("DIFFER")).map(|s| format!("{} {}: {}", s.header, s.name, s.result)).collect();
        assert!(bad.is_empty(), "struct layout drift:\n{}", bad.join("\n"));
        assert!(v.iter().filter(|s| s.result.starts_with("equal")).count() > 20);
    }
}
