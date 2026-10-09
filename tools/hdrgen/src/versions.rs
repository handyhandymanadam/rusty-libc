use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const LIBS: [&str; 9] = [
    "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libutil.so.1", "libresolv.so.2", "libanl.so.1", "ld-linux-x86-64.so.2",
];
const INTERPOSE: [&str; 11] = [
    "malloc", "free", "calloc", "realloc", "memalign", "aligned_alloc", "posix_memalign", "valloc", "pvalloc", "malloc_usable_size", "reallocarray",
];

#[derive(Clone)]
struct Sym {
    name: String,
    version: Option<String>,
    default: bool,
    ty: String,
    bind: String,
    size: i64,
}

struct Info {
    soname: Option<String>,
    verdefs: Vec<(String, Option<String>)>,
    symbols: Vec<Sym>,
}

fn vkey(v: &str) -> (u8, Vec<u64>, String) {
    if let Some(rest) = v.strip_prefix("GLIBC_") {
        let parts: Option<Vec<u64>> = rest.split('.').map(|x| x.parse().ok()).collect();
        if let Some(p) = parts {
            if !rest.is_empty() {
                return (0, p, String::new());
            }
        }
    }
    (1, vec![], v.to_string())
}

fn readelf(args: &[&str], path: &str) -> String {
    let o = Command::new("readelf").arg("-W").args(args).arg(path).env("LC_ALL", "C").output().expect("readelf");
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn parse(path: &str) -> Info {
    let mut verdefs: Vec<(String, Option<String>)> = Vec::new();
    let mut soname = None;
    let mut cur: Option<usize> = None;
    for line in readelf(&["-V"], path).lines() {
        if let Some(p) = line.find("Index:").filter(|_| line.contains("Cnt:")) {
            let rest = &line[p..];
            if let Some(n) = rest.find("Name: ") {
                let name = rest[n + 6..].split_whitespace().next().unwrap_or("").to_string();
                if line.contains("BASE") {
                    soname = Some(name);
                    cur = None;
                    continue;
                }
                verdefs.push((name, None));
                cur = Some(verdefs.len() - 1);
                continue;
            }
        }
        if let Some(p) = line.find("Parent ") {
            if let (Some(c), Some(colon)) = (cur, line[p..].find(": ")) {
                let parent = line[p + colon + 2..].split_whitespace().next().unwrap_or("").to_string();
                verdefs[c].1 = Some(parent);
            }
        }
    }
    let mut symbols = Vec::new();
    for line in readelf(&["--dyn-syms"], path).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || !f[0].ends_with(':') || f[0] == "Num:" {
            continue;
        }
        if f[6] == "UND" || f[6] == "ABS" {
            continue;
        }
        let name = f[7];
        let size: i64 = f[2].parse().unwrap_or(0);
        if let Some(at) = name.find('@') {
            let (n, rest) = name.split_at(at);
            let (default, ver) = if let Some(v) = rest.strip_prefix("@@") { (true, v) } else { (false, &rest[1..]) };
            symbols.push(Sym { name: n.to_string(), version: Some(ver.to_string()), default, ty: f[3].into(), bind: f[4].into(), size });
        } else {
            symbols.push(Sym { name: name.to_string(), version: None, default: true, ty: f[3].into(), bind: f[4].into(), size });
        }
    }
    Info { soname, verdefs, symbols }
}

fn jstr(s: &str) -> String {
    Value::String(s.to_string()).to_string()
}

fn to_json(i: &Info) -> String {
    let opt = |o: &Option<String>| o.as_ref().map(|s| jstr(s)).unwrap_or("null".into());
    let mut s = String::from("{\n");
    s.push_str(&format!(" \"soname\": {},\n", opt(&i.soname)));
    s.push_str(" \"verdefs\": [\n");
    let vd: Vec<String> = i.verdefs.iter().map(|(n, p)| format!("  {{\n   \"name\": {},\n   \"parent\": {}\n  }}", jstr(n), opt(p))).collect();
    s.push_str(&vd.join(",\n"));
    s.push_str("\n ],\n \"symbols\": [\n");
    let sy: Vec<String> = i
        .symbols
        .iter()
        .map(|y| {
            format!(
                "  {{\n   \"name\": {},\n   \"version\": {},\n   \"default\": {},\n   \"type\": {},\n   \"bind\": {},\n   \"size\": {}\n  }}",
                jstr(&y.name), opt(&y.version), y.default, jstr(&y.ty), jstr(&y.bind), y.size
            )
        })
        .collect();
    s.push_str(&sy.join(",\n"));
    s.push_str("\n ]\n}");
    s
}

fn from_json(text: &str) -> Info {
    let v: Value = serde_json::from_str(text).unwrap();
    let optstr = |x: &Value| x.as_str().map(String::from);
    Info {
        soname: optstr(&v["soname"]),
        verdefs: v["verdefs"].as_array().unwrap().iter().map(|d| (d["name"].as_str().unwrap().to_string(), optstr(&d["parent"]))).collect(),
        symbols: v["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| Sym {
                name: s["name"].as_str().unwrap().into(),
                version: optstr(&s["version"]),
                default: s["default"].as_bool().unwrap(),
                ty: s["type"].as_str().unwrap().into(),
                bind: s["bind"].as_str().unwrap().into(),
                size: s["size"].as_i64().unwrap(),
            })
            .collect(),
    }
}

fn script(nodes: &[(String, Option<String>)], by_node: &BTreeMap<String, BTreeSet<String>>, local: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    for (idx, (n, parent)) in nodes.iter().enumerate() {
        out.push(format!("{n} {{"));
        if let Some(names) = by_node.get(n) {
            if !names.is_empty() {
                out.push("  global:".into());
                for s in names {
                    out.push(format!("    {s};"));
                }
            }
        }
        if local && idx == nodes.len() - 1 {
            out.push("  local:\n    *;".into());
        }
        out.push(format!("}}{};", parent.as_ref().filter(|p| !p.is_empty()).map(|p| format!(" {p}")).unwrap_or_default()));
    }
    out.join("\n") + "\n"
}

pub fn versions(root: &Path, libdir: &str, out: Option<&Path>) {
    let out = out.map(|p| p.to_path_buf()).unwrap_or_else(|| root.join("crates/rusty-libc-cabi/shared"));
    fs::create_dir_all(&out).unwrap();
    let mut info: Vec<(String, Info)> = Vec::new();
    for lib in LIBS {
        let p = format!("{libdir}/{lib}");
        if !Path::new(&p).exists() {
            eprintln!("missing {p}");
            continue;
        }
        let i = parse(&p);
        fs::write(out.join(format!("{lib}.json")), to_json(&i) + "\n").unwrap();
        info.push((lib.to_string(), i));
    }
    let get = |l: &str| info.iter().find(|(n, _)| n == l).map(|(_, i)| i).unwrap();
    let libc_nodes: BTreeMap<String, Option<String>> = get("libc.so.6").verdefs.iter().cloned().collect();
    let mut allnodes: BTreeSet<String> = libc_nodes.keys().cloned().collect();
    for (lib, i) in &info {
        if lib != "ld-linux-x86-64.so.2" {
            allnodes.extend(i.verdefs.iter().map(|d| d.0.clone()));
        }
    }
    let mut sorted: Vec<&String> = allnodes.iter().collect();
    sorted.sort_by_key(|n| vkey(n));
    let mut nodes: Vec<(String, Option<String>)> = Vec::new();
    let mut prev: Option<String> = None;
    let mut added: Vec<String> = Vec::new();
    for n in sorted {
        if let Some(p) = libc_nodes.get(n) {
            nodes.push((n.clone(), p.clone()));
        } else {
            nodes.push((n.clone(), prev.clone()));
            added.push(n.clone());
        }
        prev = Some(n.clone());
    }
    nodes.sort_by_key(|t| t.0 == "GLIBC_PRIVATE");
    let mut by_node: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut compat: Vec<String> = Vec::new();
    for (lib, i) in &info {
        if lib == "ld-linux-x86-64.so.2" {
            continue;
        }
        for s in &i.symbols {
            let Some(v) = &s.version else { continue };
            if s.default {
                by_node.entry(v.clone()).or_default().insert(s.name.clone());
            } else {
                compat.push(format!("{}@{} {} {} {} {}", s.name, v, s.ty, s.bind, s.size, lib));
            }
        }
    }
    let extra_path = out.join("extra-exports.txt");
    if let Ok(t) = fs::read_to_string(&extra_path) {
        for line in t.lines() {
            let f: Vec<&str> = line.split('#').next().unwrap().split_whitespace().collect();
            if f.len() >= 2 {
                by_node.entry(f[1].to_string()).or_default().insert(f[0].to_string());
            }
        }
    }
    fs::write(out.join("libc.map"), script(&nodes, &by_node, true)).unwrap();
    compat.sort();
    fs::write(out.join("compat.txt"), compat.join("\n") + "\n").unwrap();
    for (lib, i) in &info {
        if lib == "libc.so.6" || lib == "ld-linux-x86-64.so.2" {
            continue;
        }
        let ns = i.verdefs.clone();
        let mut stub_syms: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for d in &i.verdefs {
            if !d.0.starts_with("GLIBC_ABI") {
                stub_syms.entry(d.0.clone()).or_default().insert(format!("__stub_{}", d.0.replace('.', "_")));
            }
        }
        fs::write(out.join(format!("{lib}.stub.map")), script(&ns, &stub_syms, true)).unwrap();
    }
    let li = get("ld-linux-x86-64.so.2");
    let mut lby: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for s in &li.symbols {
        if let (Some(v), true) = (&s.version, s.default) {
            lby.entry(v.clone()).or_default().insert(s.name.clone());
        }
    }
    if let Ok(t) = fs::read_to_string(root.join("crates/rusty-libc-ldso/exports.txt")) {
        for line in t.lines() {
            let l = line.split('#').next().unwrap().trim();
            if !l.is_empty() {
                lby.entry("GLIBC_PRIVATE".into()).or_default().insert(l.to_string());
            }
        }
    }
    fs::write(out.join("ld.map"), script(&li.verdefs, &lby, true)).unwrap();
    let mut dynl: BTreeSet<String> = BTreeSet::new();
    for (lib, i) in &info {
        if lib == "ld-linux-x86-64.so.2" {
            continue;
        }
        for s in &i.symbols {
            if s.version.is_some() && (s.ty == "OBJECT" || s.ty == "TLS" || (s.default && INTERPOSE.contains(&s.name.as_str()))) {
                dynl.insert(s.name.clone());
            }
        }
    }
    let mut t = String::from("{\n");
    for n in &dynl {
        t.push_str(&format!("  {n};\n"));
    }
    t.push_str("};\n");
    fs::write(out.join("libc.dynlist"), t).unwrap();
    let nd: usize = by_node.values().map(|v| v.len()).sum();
    println!("libc.map: {} nodes ({} added), {} default symbols, {} compat symbols, {} interposable", nodes.len(), added.len(), nd, compat.len(), dynl.len());
}

const STUB_LIBS: [&str; 8] = ["libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libutil.so.1", "libresolv.so.2", "libanl.so.1"];

fn stub_script(verdefs: &[(String, Option<String>)], markers: &BTreeMap<String, String>) -> String {
    let mut out: Vec<String> = Vec::new();
    let names: Vec<&String> = verdefs.iter().map(|d| &d.0).collect();
    for (idx, (n, parent)) in verdefs.iter().enumerate() {
        out.push(format!("{n} {{"));
        if let Some(m) = markers.get(n) {
            out.push(format!("  global:\n    {m};"));
        }
        if idx == verdefs.len() - 1 {
            out.push("  local:\n    stub_*;".into());
        }
        let par = parent.as_ref().filter(|p| !p.is_empty() && names.contains(p)).map(|p| format!(" {p}")).unwrap_or_default();
        out.push(format!("}}{par};"));
    }
    out.join("\n") + "\n"
}

pub fn stubsrc(root: &Path, lib: &str, base: &Path) -> String {
    let shared = root.join("crates/rusty-libc-cabi/shared");
    let info = from_json(&fs::read_to_string(shared.join(format!("{lib}.json"))).unwrap());
    let mut verdefs = info.verdefs.clone();
    verdefs.sort_by_key(|d| d.0 == "GLIBC_PRIVATE");
    let mut asm: Vec<String> = Vec::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for (i, s) in info.symbols.iter().enumerate() {
        let Some(ver) = &s.version else { continue };
        let sym = format!("stub_{i}");
        let sec = match s.ty.as_str() {
            "FUNC" | "IFUNC" => ".text",
            "OBJECT" => ".bss",
            "TLS" => ".tbss",
            _ => continue,
        };
        used.insert(ver.clone());
        asm.push(format!("    .section {}", if sec == ".tbss" { ".tbss,\"awT\",@nobits" } else { sec }));
        if s.ty == "OBJECT" {
            asm.push("    .balign 32".into());
        }
        if s.ty == "TLS" {
            asm.push("    .balign 16".into());
        }
        asm.push(format!("    .{} {}", if s.bind == "WEAK" { "weak" } else { "globl" }, sym));
        let kind = match s.ty.as_str() {
            "FUNC" | "IFUNC" => "function",
            "OBJECT" => "object",
            _ => "tls_object",
        };
        asm.push(format!("    .type {sym}, @{kind}"));
        let size = if s.ty != "FUNC" && s.ty != "IFUNC" { s.size } else { 1 };
        asm.push(format!("    .size {sym}, {size}"));
        asm.push(format!("    .symver {sym}, {}{}{}", s.name, if s.default { "@@" } else { "@" }, ver));
        asm.push(format!("{sym}:"));
        if sec == ".text" {
            asm.push("    ret".into());
        } else {
            asm.push(format!("    .zero {}", s.size.max(0)));
        }
    }
    let mut markers: BTreeMap<String, String> = BTreeMap::new();
    for d in &verdefs {
        if !used.contains(&d.0) && !d.0.starts_with("GLIBC_ABI") {
            markers.insert(d.0.clone(), format!("__stub_{}", d.0.replace('.', "_")));
        }
    }
    for d in &verdefs {
        if let Some(m) = markers.get(&d.0) {
            asm.push(format!("    .globl {m}\n    .set {m}, 0"));
        }
    }
    asm.push("    .section .note.GNU-stack,\"\",@progbits".into());
    let b = base.to_string_lossy().to_string();
    fs::write(format!("{b}.s"), asm.join("\n") + "\n").unwrap();
    fs::write(format!("{b}.map"), stub_script(&verdefs, &markers)).unwrap();
    info.soname.clone().unwrap_or_else(|| lib.to_string())
}

fn stub(root: &Path, lib: &str, outdir: &Path) -> usize {
    let base = outdir.join(lib);
    let soname = stubsrc(root, lib, &base);
    let b = base.to_string_lossy().to_string();
    let st = Command::new("as").args(["-o", &format!("{b}.o"), &format!("{b}.s")]).status().unwrap();
    assert!(st.success(), "as failed for {lib}");
    let st = Command::new("ld")
        .args(["-shared", "-soname", &soname, &format!("--version-script={b}.map"), "--hash-style=both", "-z", "noexecstack", "-z", "norelro", &format!("{b}.o"), "-o", &b])
        .status()
        .unwrap();
    assert!(st.success(), "ld failed for {lib}");
    for ext in [".s", ".map", ".o"] {
        let _ = fs::remove_file(format!("{b}{ext}"));
    }
    let shared = root.join("crates/rusty-libc-cabi/shared");
    let info = from_json(&fs::read_to_string(shared.join(format!("{lib}.json"))).unwrap());
    info.symbols.iter().filter(|s| s.version.is_some()).count()
}

pub fn linkstubs(root: &Path, outdir: &Path) {
    fs::create_dir_all(outdir).unwrap();
    let mut total = 0;
    for lib in STUB_LIBS {
        total += stub(root, lib, outdir);
    }
    println!("link stubs: {} libraries, {} symbols in {}", STUB_LIBS.len(), total, outdir.display());
}
