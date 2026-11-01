//! The data model of a hand-described header and the printer that turns it into C text.
//!
//! A header is an ordered list of items. Constants, typedefs, struct/union/enum definitions and declarations
//! are data. What the C preprocessor must see (function-like macros, feature-test conditionals, `_Generic`
//! macros, `static inline` functions) cannot be produced by Rust at build time of the user's program, so it is
//! held as C text in `Raw` items, each tagged with the reason it has to stay text (`hdrgen exceptions` lists
//! them). Conditionals are `Gate` items whose branch heads are the directive text.

use std::fmt::Write;

#[derive(Clone, Copy, Debug)]
pub enum V {
    Dec(i64),
    Hex(u64),
    /// any other C expression or token sequence, printed as written after one space
    Txt(&'static str),
    /// the text after the macro name exactly as written (its own separator: tabs, several spaces, a comment, a
    /// backslash continuation)
    Sp(&'static str),
}

/// Why a piece of C text stays text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// a macro the C or POSIX standard requires to be a macro (assert, va_*, offsetof, WIF*, S_IS*, CMSG_*, ...)
    StdMacro,
    /// a feature-test conditional (#if/#ifdef on _GNU_SOURCE, __USE_*, ...)
    FeatureTest,
    /// a macro built on _Generic
    Generic,
    /// a static inline function or other function definition
    StaticInline,
    /// an attribute or declaration-modifier macro
    Attribute,
    /// a function-like macro glibc ships as a macro (not required by a standard)
    GlibcMacro,
    /// anything else (preprocessor directives, C++ guards, layout-dependent text, ...)
    Other,
}

impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Reason::StdMacro => "standard-required macro",
            Reason::FeatureTest => "feature-test conditional",
            Reason::Generic => "_Generic",
            Reason::StaticInline => "static inline",
            Reason::Attribute => "attribute",
            Reason::GlibcMacro => "glibc function-like macro",
            Reason::Other => "other",
        }
    }
}

pub struct Branch {
    /// directive text after the `#` and its indentation: "ifdef _GNU_SOURCE", "else", "elif defined X"
    pub head: &'static str,
    pub items: &'static [Item],
}

#[derive(Clone, Copy)]
pub enum Item {
    Blank,
    Comment(&'static str),
    Undef(&'static str),
    /// `<stdint.h>` or `"x.h"`
    Include(&'static str),
    /// `#define NAME value` lines
    Consts(&'static [(&'static str, V)]),
    /// the same, written with `#define` at column 0 even inside a conditional
    ConstsFlat(&'static [(&'static str, V)]),
    /// `typedef TYPE NAME;`
    Typedef(&'static str, &'static str),
    /// `HEAD{BODY}TAIL;` : a struct, union or enum definition; `body` holds the lines between the braces
    Block { head: &'static str, body: &'static [&'static str], tail: &'static str },
    /// a declaration (prototype, extern variable, odd typedef), printed as written
    Decl(&'static str),
    /// `#ifdef __cplusplus / extern "C" { / #endif` and its closing twin
    ExternBegin,
    ExternEnd,
    /// C text that has to stay text, with the reason
    Raw(Reason, &'static str),
    /// `#if`-chain: one branch per if/elif/else, then `#endif` + suffix
    Gate(&'static [Branch], &'static str),
    /// the include guard of the header: `#ifndef NAME` `#define NAME [value]` ... `#endif`
    Guard { name: &'static str, value: &'static str, end: &'static str, items: &'static [Item] },
}

pub struct Header {
    pub path: &'static str,
    pub items: &'static [Item],
}

fn spaces(out: &mut String, depth: usize) {
    out.push('#');
    for _ in 0..depth {
        out.push(' ');
    }
}

pub fn print_items(out: &mut String, items: &[Item], depth: usize) {
    for it in items {
        print_item(out, it, depth);
    }
}

pub fn print_value(out: &mut String, v: &V) {
    match v {
        V::Dec(n) => write!(out, "{n}").unwrap(),
        V::Hex(n) => write!(out, "0x{n:x}").unwrap(),
        V::Txt(t) | V::Sp(t) => out.push_str(t),
    }
}

fn print_item(out: &mut String, it: &Item, depth: usize) {
    match it {
        Item::Blank => out.push('\n'),
        Item::Comment(t) | Item::Decl(t) | Item::Raw(_, t) => {
            out.push_str(t);
            out.push('\n');
        }
        Item::Undef(n) => {
            spaces(out, depth);
            out.push_str("undef ");
            out.push_str(n);
            out.push('\n');
        }
        Item::Include(a) => {
            spaces(out, depth);
            out.push_str("include ");
            out.push_str(a);
            out.push('\n');
        }
        Item::Consts(cs) | Item::ConstsFlat(cs) => {
            let d = if matches!(it, Item::ConstsFlat(_)) { 0 } else { depth };
            for (n, v) in cs.iter() {
                spaces(out, d);
                out.push_str("define ");
                out.push_str(n);
                match v {
                    V::Sp(t) => out.push_str(t),
                    _ => {
                        let mut val = String::new();
                        print_value(&mut val, v);
                        if !val.is_empty() {
                            out.push(' ');
                            out.push_str(&val);
                        }
                    }
                }
                out.push('\n');
            }
        }
        Item::Typedef(t, n) => {
            out.push_str("typedef ");
            out.push_str(t);
            if !t.ends_with('*') {
                out.push(' ');
            }
            out.push_str(n);
            out.push_str(";\n");
        }
        Item::Block { head, body, tail } => {
            out.push_str(head);
            out.push('{');
            out.push_str(&body.join("\n"));
            out.push('}');
            out.push_str(tail);
            out.push_str(";\n");
        }
        Item::ExternBegin => out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n"),
        Item::ExternEnd => out.push_str("#ifdef __cplusplus\n}\n#endif\n"),
        Item::Gate(branches, end) => {
            for b in branches.iter() {
                spaces(out, depth);
                out.push_str(b.head);
                out.push('\n');
                print_items(out, b.items, depth + 1);
            }
            spaces(out, depth);
            out.push_str("endif");
            out.push_str(end);
            out.push('\n');
        }
        Item::Guard { name, value, end, items } => {
            out.push_str("#ifndef ");
            out.push_str(name);
            out.push_str("\n#define ");
            out.push_str(name);
            if !value.is_empty() {
                out.push(' ');
                out.push_str(value);
            }
            out.push('\n');
            print_items(out, items, 0);
            out.push_str("#endif");
            out.push_str(end);
            out.push('\n');
        }
    }
}

impl Header {
    pub fn render(&self) -> String {
        let mut s = String::new();
        print_items(&mut s, self.items, 0);
        s
    }
}

// ---------------------------------------------------------------- exceptions report

pub struct Exception {
    pub header: String,
    pub reason: Reason,
    pub what: String,
}

fn first_line(t: &str) -> String {
    let l = t.lines().next().unwrap_or("").trim();
    let mut s: String = l.chars().take(70).collect();
    if l.chars().count() > 70 {
        s.push_str("...");
    }
    s
}

fn collect(h: &str, items: &'static [Item], out: &mut Vec<Exception>) {
    for it in items {
        match it {
            Item::Raw(r, t) => out.push(Exception { header: h.to_string(), reason: *r, what: first_line(t) }),
            Item::Gate(branches, _) => {
                for b in branches.iter() {
                    if b.head != "else" {
                        out.push(Exception { header: h.to_string(), reason: gate_reason(b.head), what: format!("#{}", first_line(b.head)) });
                    }
                    collect(h, b.items, out);
                }
            }
            Item::Guard { items, .. } => collect(h, items, out),
            Item::Block { body, head, .. }
                if body.iter().any(|l| l.starts_with('#')) => {
                    out.push(Exception { header: h.to_string(), reason: Reason::FeatureTest, what: format!("conditional inside {}", first_line(head)) });
                }
            _ => {}
        }
    }
}

/// A conditional is a feature-test one when it asks about a feature-test or glibc __USE_ macro; the rest
/// (duplicate-definition guards, byte order, C++) are "other".
fn gate_reason(head: &str) -> Reason {
    const FEATURE: [&str; 17] = ["__has_builtin", "__FLT_EVAL", "__BYTE_ORDER", "__ASSERT", "__cplusplus", "_SOURCE", "__USE_", "__RLIBC_", "_XOPEN", "__STDC_", "__GLIBC_USE", "__STRICT_ANSI__", "__GNUC", "_ISOC", "_FORTIFY", "__GLIBC__", "__OPTIMIZE__"];
    if FEATURE.iter().any(|f| head.contains(f)) {
        Reason::FeatureTest
    } else {
        Reason::Other
    }
}

pub fn exceptions(all: &'static [&'static Header]) -> Vec<Exception> {
    let mut v = Vec::new();
    for h in all {
        collect(h.path, h.items, &mut v);
    }
    // the C text that cbindgen puts into the headers made from the crates (before/after the generated part)
    for (name, t) in crate::hdr_cb::ALL {
        for (part, x) in [("header", &t.header), ("after_includes", &t.after_includes), ("trailer", &t.trailer)] {
            if let Some((items, _)) = x {
                collect(&format!("cbindgen:{name} ({part})"), items, &mut v);
            }
        }
    }
    v
}
