use std::fmt::Write;

#[derive(Clone, Copy, Debug)]
pub enum V {
    Dec(i64),
    Hex(u64),
    Txt(&'static str),
    Sp(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Reason {
    StdMacro,
    FeatureTest,
    Generic,
    StaticInline,
    Attribute,
    GlibcMacro,
    Other,
}

pub struct Branch {
    pub head: &'static str,
    pub items: &'static [Item],
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Item {
    Blank,
    Comment(&'static str),
    Undef(&'static str),
    Include(&'static str),
    Consts(&'static [(&'static str, V)]),
    ConstsFlat(&'static [(&'static str, V)]),
    Typedef(&'static str, &'static str),
    Block { head: &'static str, body: &'static [&'static str], tail: &'static str },
    Decl(&'static str),
    ExternBegin,
    ExternEnd,
    Raw(Reason, &'static str),
    Gate(&'static [Branch], &'static str),
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
