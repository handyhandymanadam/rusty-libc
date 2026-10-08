use crate::math::{self, Math};
use crate::specs::{build_specs, item_src, Spec, Subst};
use crate::sys::{self, Sys};
use crate::text::replace_word;
use regex_lite::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Gen {
    pub root: PathBuf,
    pub tmp: PathBuf,
}

fn load_mem_items(root: &Path) -> BTreeMap<String, String> {
    let re = Regex::new(r#"(?s)((?:///[^\n]*\n|#\[[^\n]*\n)+)(pub unsafe extern "C" fn (\w+)\b.*?\n\}\n)"#).unwrap();
    let mut items = BTreeMap::new();
    for (krate, name) in item_src() {
        let text = fs::read_to_string(root.join("crates").join(krate).join("src").join(name)).unwrap();
        for m in re.captures_iter(&text) {
            items.insert(m[3].to_string(), format!("{}{}", &m[1], &m[2]));
        }
    }
    items
}

fn pick_items(root: &Path, path: &str, names: &[String]) -> Vec<String> {
    let re = Regex::new(r#"(?s)((?:///[^\n]*\n|#\[[^\n]*\n)*)(pub (?:unsafe )?extern "C" fn (\w+)\b.*?\n\}\n|pub static mut (\w+)\b[^\n]*;\n)"#).unwrap();
    let text = fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    for m in re.captures_iter(&text) {
        let is_fn = m.get(3).is_some();
        let name = m.get(3).or(m.get(4)).unwrap().as_str().to_string();
        if names.contains(&name) && !m[1].contains("not(feature") {
            let mut attrs = m[1].to_string();
            if !attrs.contains("no_mangle") && is_fn {
                attrs.push_str("#[unsafe(no_mangle)]\n");
            }
            found.insert(name, format!("{}{}", attrs, &m[2]));
        }
    }
    let missing: Vec<&String> = names.iter().filter(|n| !found.contains_key(*n)).collect();
    if !missing.is_empty() {
        panic!("hdrgen: {path}: not found: {missing:?}");
    }
    names.iter().map(|n| found[n].clone()).collect()
}

fn filter_exports(src: &str, spec: &Spec) -> String {
    let lines: Vec<&str> = src.split_inclusive('\n').collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let fn_re = Regex::new(r#"^pub (?:unsafe )?extern "C" fn (\w+)"#).unwrap();
    let nm = "#[unsafe(no_mangle)]\n";
    let mut lines2: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    if spec.only.is_some() {
        let mut i = 0;
        let mut res: Vec<String> = Vec::new();
        while i < lines2.len() {
            if lines2[i] == nm {
                let mut j = i + 1;
                while j < lines2.len() && lines2[j].starts_with("#[") {
                    j += 1;
                }
                if j < lines2.len() && lines2[j].starts_with("pub static") {
                    i += 1;
                    continue;
                }
            }
            res.push(lines2[i].clone());
            i += 1;
        }
        lines2 = res;
    }
    let mut i = 0;
    while i < lines2.len() {
        if lines2[i] == nm {
            let mut j = i + 1;
            while j < lines2.len() && lines2[j].starts_with("#[") {
                j += 1;
            }
            if j < lines2.len() {
                if let Some(m) = fn_re.captures(&lines2[j]) {
                    let name = m[1].to_string();
                    let ok = match (&spec.only, &spec.skip) {
                        (Some(o), _) => o.contains(&name),
                        (None, Some(s)) => !s.contains(&name),
                        _ => true,
                    };
                    if !ok {
                        i += 1;
                        continue;
                    }
                }
            }
        }
        out.push(lines2[i].clone());
        i += 1;
    }
    out.concat()
}

fn strip_inner(src: &str) -> String {
    let inner_attr = Regex::new(r"^#!\[.*\]$").unwrap();
    let mut out = String::with_capacity(src.len());
    for l in src.split_inclusive('\n') {
        let body = l.strip_suffix('\n');
        if l.starts_with("//!") && body.is_some() {
            continue;
        }
        if let Some(b) = body {
            if inner_attr.is_match(b) {
                continue;
            }
        }
        out.push_str(l);
    }
    out
}

impl Gen {
    pub fn new(root: &Path, tmp: &Path) -> Gen {
        fs::create_dir_all(tmp).unwrap();
        Gen { root: root.to_path_buf(), tmp: tmp.to_path_buf() }
    }

    pub fn cbindgen_headers(&self) -> BTreeMap<String, String> {
        let mut specs = build_specs();
        let sys = Sys::new(&self.root);
        let math = Math::new(&self.root);
        let mut sys_names: Vec<String> = sys::sys_fns().iter().map(|(h, _)| h.to_string()).collect();
        sys_names.extend(sys::CONST_ONLY.iter().map(|s| s.to_string()));
        sys_names.push("sys/types".into());
        for h in sys_names {
            if let Some(s) = specs.iter_mut().find(|s| s.name == h) {
                s.sys = true;
            } else {
                specs.push(Spec { name: h.clone(), config: h.replace('/', "_"), sys: true, ..Default::default() });
            }
        }
        let items = load_mem_items(&self.root);
        let mut out = BTreeMap::new();
        for spec in &specs {
            let mut parts: Vec<String> = Vec::new();
            for f in &spec.files {
                parts.push(fs::read_to_string(self.root.join(f)).unwrap_or_else(|e| panic!("{f}: {e}")));
            }
            for f in &spec.fns {
                parts.push(items.get(f).unwrap_or_else(|| panic!("fn {f} not found")).clone());
            }
            for (path, names) in &spec.picks {
                parts.extend(pick_items(&self.root, path, names));
            }
            if spec.sys {
                parts.push(sys.header_source(&spec.name));
            }
            let mut src = parts.join("\n").replace("#[cfg_attr(feature = \"export\", unsafe(no_mangle))]", "#[unsafe(no_mangle)]");
            if spec.only.is_some() || spec.skip.is_some() {
                src = filter_exports(&src, spec);
            }
            src = strip_inner(&src);
            src = replace_word(&src, "VaList", "va_list", false);
            for s in &spec.subst {
                match s {
                    Subst::Word(a, b) => src = replace_word(&src, a, b, false),
                    Subst::Lit(a, b) => src = src.replace(a, b),
                    Subst::None => {}
                }
            }
            if spec.tiers {
                src = math.inject_cfg(&src);
            }
            let tmp = self.tmp.join(format!("{}.rs", spec.name.replace('/', "_")));
            fs::write(&tmp, &src).unwrap();
            let cfg_path = self.root.join("cbindgen").join(format!("{}.toml", spec.config));
            let mut cfg = cbindgen::Config::from_file(&cfg_path).unwrap_or_else(|e| panic!("{}: {e}", cfg_path.display()));
            if let Some(t) = crate::hdr_cb::lookup(&spec.config) {
                let render = |x: (&'static [crate::model::Item], bool)| {
                    let mut s = String::new();
                    crate::model::print_items(&mut s, x.0, 0);
                    if x.1 {
                        s.pop();
                    }
                    s
                };
                cfg.header = t.header.map(render);
                cfg.after_includes = t.after_includes.map(render);
                cfg.trailer = t.trailer.map(render);
            }
            let bindings = cbindgen::Builder::new().with_config(cfg).with_src(&tmp).generate().unwrap_or_else(|e| panic!("cbindgen {}: {e}", spec.name));
            let dest = self.tmp.join(format!("{}.h", spec.name.replace('/', "_")));
            bindings.write_to_file(&dest);
            let mut text = fs::read_to_string(&dest).unwrap();
            if spec.sys {
                text = sys::finish(&text, &spec.name);
            }
            out.insert(format!("{}.h", spec.name), text);
        }
        out.insert("bits/rlibc-mathaliases.h".into(), math.alias_header());
        out.insert("bits/rlibc-mathldcalls.h".into(), math.longdouble_header());
        out.insert("bits/rlibc-mathquadcalls.h".into(), math.quad_header());
        out.insert("complex.h".into(), math::complex_header());
        out
    }
}

fn attr_table() -> BTreeMap<&'static str, Vec<(String, String)>> {
    let p = |a: &str| format!("__THROW __attribute_pure__ __nonnull (({a}))");
    let t = |a: &str| format!("__THROW __nonnull (({a}))");
    let mut m: BTreeMap<&'static str, Vec<(String, String)>> = BTreeMap::new();
    let mut s: Vec<(String, String)> = Vec::new();
    for n in "memcpy memmove memccpy mempcpy strcpy stpcpy strncpy stpncpy strcat strncat strsep".split(' ') {
        s.push((n.into(), t("1, 2")));
    }
    s.push(("memset".into(), t("1")));
    s.push(("strxfrm".into(), t("2")));
    s.push(("strtok".into(), t("2")));
    s.push(("strtok_r".into(), t("2, 3")));
    for n in "memcmp strcmp strncmp strcoll strcspn strspn strpbrk strstr strverscmp".split(' ') {
        s.push((n.into(), p("1, 2")));
    }
    for n in "memchr rawmemchr memrchr strchr strrchr strchrnul strlen strnlen".split(' ') {
        s.push((n.into(), p("1")));
    }
    s.push(("memmem".into(), p("1, 3")));
    s.push(("strdup".into(), "__THROW __attribute_malloc__ __nonnull ((1))".into()));
    s.push(("strndup".into(), "__THROW __attribute_malloc__ __nonnull ((1))".into()));
    s.push(("strerror".into(), "__THROW".into()));
    m.insert("string.h", s);
    m.insert("strings.h", vec![
        ("bcmp".into(), p("1, 2")), ("bcopy".into(), t("1, 2")), ("bzero".into(), t("1")), ("index".into(), p("1")), ("rindex".into(), p("1")),
        ("strcasecmp".into(), p("1, 2")), ("strncasecmp".into(), p("1, 2")),
        ("ffs".into(), "__THROW __attribute_const__".into()), ("ffsl".into(), "__THROW __attribute_const__".into()), ("ffsll".into(), "__THROW __attribute_const__".into()),
    ]);
    let mut sl: Vec<(String, String)> = Vec::new();
    for n in ["atoi", "atol", "atoll", "atof"] {
        sl.push((n.into(), p("1")));
    }
    for n in ["abs", "labs", "llabs"] {
        sl.push((n.into(), "__THROW __attribute_const__".into()));
    }
    for n in ["strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof", "strtold"] {
        sl.push((n.into(), t("1")));
    }
    sl.push(("getenv".into(), "__THROW __nonnull ((1))".into()));
    sl.push(("malloc".into(), "__THROW __attribute_malloc__".into()));
    sl.push(("calloc".into(), "__THROW __attribute_malloc__".into()));
    m.insert("stdlib.h", sl);
    m.insert("ctype.h", "isalnum isalpha iscntrl isdigit islower isgraph isprint ispunct isspace isupper isxdigit isblank tolower toupper isascii toascii".split(' ').map(|n| (n.to_string(), "__THROW".to_string())).collect());
    m
}

fn add_attrs_to(text: &str, name: &str, attr: &str) -> String {
    let b = text.as_bytes();
    let mut ls = 0usize;
    let name_pat = name.as_bytes();
    while ls <= text.len() {
        let le = text[ls..].find('\n').map(|p| ls + p).unwrap_or(text.len());
        let line = &text[ls..le];
        let trimmed = line.trim_start_matches([' ', '\t']);
        let skip = trimmed.starts_with('*') || trimmed.starts_with('/');
        if !skip {
            let lb = line.as_bytes();
            let mut idx = 0;
            let mut hit: Option<usize> = None;
            while idx < lb.len() {
                let c = lb[idx];
                if (c == b' ' || c == b'*') && lb[idx + 1..].starts_with(name_pat) {
                    let mut k = idx + 1 + name_pat.len();
                    while k < lb.len() && (lb[k] == b' ' || lb[k] == b'\t') {
                        k += 1;
                    }
                    if k < lb.len() && lb[k] == b'(' {
                        hit = Some(ls + k);
                        break;
                    }
                }
                if matches!(c, b';' | b'{' | b'}' | b'(' | b')') {
                    break;
                }
                idx += 1;
            }
            if let Some(par) = hit {
                let mut t = par + 1;
                while t < b.len() && !matches!(b[t], b';' | b'{' | b'}') {
                    t += 1;
                }
                if t < b.len() && b[t] == b';' {
                    let mut r = t;
                    while r > par && (b[r - 1] == b' ' || b[r - 1] == b'\t') {
                        r -= 1;
                    }
                    if r > par && b[r - 1] == b')' {
                        return format!("{} {};{}", &text[..r], attr, &text[t + 1..]);
                    }
                }
            }
        }
        if le >= text.len() {
            break;
        }
        ls = le + 1;
    }
    text.to_string()
}

pub fn add_attributes(files: &mut BTreeMap<String, String>) {
    for (hdr, table) in attr_table() {
        if let Some(text) = files.get_mut(hdr) {
            let mut t = text.clone();
            for (name, attr) in table {
                t = add_attrs_to(&t, &name, &attr);
            }
            *text = t;
        }
    }
}

pub fn untypedef(files: &mut BTreeMap<String, String>) {
    for (hdr, names) in [("stdlib.h", ["random_data", "drand48_data"])] {
        if let Some(text) = files.get_mut(hdr) {
            for n in names {
                let open = format!("typedef struct {n} {{");
                let close = format!("\n}} {n};");
                if let Some(s) = text.find(&open) {
                    let inner_start = s + open.len();
                    if let Some(c) = text[inner_start..].find(&close) {
                        let inner = text[inner_start..inner_start + c].to_string();
                        let end = inner_start + c + close.len();
                        *text = format!("{}struct {n} {{{}\n}};{}", &text[..s], inner, &text[end..]);
                    }
                }
            }
        }
    }
}

fn has_define(text: &str, name: &str) -> bool {
    let b = text.as_bytes();
    let isw = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for (i, _) in text.match_indices('#') {
        let mut k = i + 1;
        while k < b.len() && b[k].is_ascii_whitespace() {
            k += 1;
        }
        if !text[k..].starts_with("define") {
            continue;
        }
        k += 6;
        let ws = k;
        while k < b.len() && b[k].is_ascii_whitespace() {
            k += 1;
        }
        if k == ws {
            continue;
        }
        if text[k..].starts_with(name) {
            let e = k + name.len();
            if e >= b.len() || !isw(b[e]) {
                return true;
            }
        }
    }
    false
}

fn find_guard(text: &str) -> Option<usize> {
    let mut ls = 0;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut offs = Vec::new();
    for l in &lines {
        offs.push(ls);
        ls += l.len();
    }
    let isw = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for i in 0..lines.len().saturating_sub(1) {
        let l = lines[i];
        let Some(body) = l.strip_suffix('\n') else { continue };
        let Some(r) = body.strip_prefix('#') else { continue };
        let r = r.trim_start();
        let Some(r) = r.strip_prefix("ifndef") else { continue };
        if !r.starts_with([' ', '\t']) {
            continue;
        }
        let r = r.trim_start();
        let id_len = r.bytes().take_while(|c| isw(*c)).count();
        if id_len == 0 || !r[id_len..].chars().all(|c| c == ' ' || c == '\t') {
            continue;
        }
        let id = &r[..id_len];
        let n = lines[i + 1];
        let Some(nb) = n.strip_suffix('\n') else { continue };
        let Some(r2) = nb.strip_prefix('#') else { continue };
        let r2 = r2.trim_start();
        let Some(r2) = r2.strip_prefix("define") else { continue };
        if !r2.starts_with([' ', '\t']) {
            continue;
        }
        let r2 = r2.trim_start();
        if r2.starts_with(id) && r2.as_bytes().get(id.len()).map_or(true, |c| !isw(*c)) {
            return Some(offs[i + 1] + n.len());
        }
    }
    None
}

pub fn add_features_include(files: &mut BTreeMap<String, String>) {
    let skip = ["features.h", "limits.h", "stdint.h", "gnu-versions.h"];
    for (path, text) in files.iter_mut() {
        let (rel, name) = match path.rsplit_once('/') {
            Some((d, n)) => (d, n),
            None => (".", path.as_str()),
        };
        if rel == "bits" || rel.starts_with("bits/") || rel == "gnu" {
            continue;
        }
        if !name.ends_with(".h") || (rel == "." && skip.contains(&name)) || (rel == "sys" && name == "cdefs.h") {
            continue;
        }
        if text.contains("<features.h>") {
            continue;
        }
        let Some(end) = find_guard(text) else {
            eprintln!("hdrgen: no include guard, features.h not added: {path}");
            continue;
        };
        let guard: String = format!("_{}", path.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect::<String>());
        let extra = if has_define(text, &guard) { String::new() } else { format!("#ifndef {guard}\n# define {guard} 1\n#endif\n") };
        *text = format!("{}#include <features.h>\n{}{}", &text[..end], extra, &text[end..]);
    }
}

pub fn post_passes(files: &mut BTreeMap<String, String>) {
    add_attributes(files);
    untypedef(files);
    add_features_include(files);
}

pub fn full_tree(root: &Path, tmp: &Path) -> BTreeMap<String, String> {
    let g = Gen::new(root, tmp);
    let mut files: BTreeMap<String, String> = crate::hdr::ALL.iter().map(|h| (h.path.to_string(), h.render())).collect();
    for (k, v) in g.cbindgen_headers() {
        files.insert(k, v);
    }
    post_passes(&mut files);
    files
}

