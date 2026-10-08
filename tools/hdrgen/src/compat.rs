use crate::compat_table::OVERRIDES;
use crate::oldabi_table::ALIASES;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::process::Command;

fn defined_from(file: &str) -> BTreeSet<String> {
    fs::read_to_string(file).unwrap().lines().map(|l| l.trim().to_string()).collect()
}

fn nm(args: &[&str], path: &Path) -> BTreeSet<String> {
    let o = Command::new("nm").args(args).arg(path).output().expect("nm");
    let mut names = BTreeSet::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 3 {
            names.insert(p[2].to_string());
        }
    }
    names
}

pub fn oldabi(root: &Path, defined: Option<&str>) {
    let ours: BTreeSet<String> = match defined {
        Some(f) => defined_from(f),
        None => nm(&["-D", "--defined-only"], &root.join("target/shared/libc.so.6")).into_iter().map(|n| n.split('@').next().unwrap().to_string()).collect(),
    };
    let mut mapped = BTreeSet::new();
    for line in fs::read_to_string(root.join("crates/rusty-libc-cabi/shared/libc.map")).unwrap().lines() {
        let t = line.trim().trim_end_matches(';');
        if !t.is_empty() && !t.ends_with('{') && !(t.starts_with('}') || t.starts_with("global") || t.starts_with("local") || t.starts_with('*')) {
            mapped.insert(t.to_string());
        }
    }
    let mut table: Vec<(&str, &str)> = ALIASES.to_vec();
    table.sort();
    let (mut done, mut skipped): (Vec<(&str, &str)>, Vec<String>) = (vec![], vec![]);
    for (name, target) in table {
        if !mapped.contains(name) {
            skipped.push(format!("{name} (glibc does not export it)"));
        } else if !ours.contains(target) {
            skipped.push(format!("{name} (no {target} here)"));
        } else {
            done.push((name, target));
        }
    }
    let mut out: Vec<String> = vec![
        "#![allow(missing_docs)]".into(),
        "".into(),
        "core::arch::global_asm!(".into(),
        "    \".pushsection .text.rl_compat,\\\"ax\\\",@progbits\",".into(),
    ];
    for (name, target) in &done {
        out.push("    \".p2align 3\",".into());
        out.push(format!("    \".globl {name}\","));
        out.push(format!("    \".type {name}, @function\","));
        out.push(format!("    \"{name}:\","));
        out.push(format!("    \"jmp {target}\","));
    }
    out.push("    \".popsection\",".into());
    out.push(");".into());
    fs::write(root.join("crates/rusty-libc-cabi/src/compat_abi.rs"), out.join("\n") + "\n").unwrap();
    println!("{} aliases written, {} skipped", done.len(), skipped.len());
    for s in skipped {
        println!("  skipped: {s}");
    }
}

fn suffix(t: char) -> &'static str {
    match t {
        'd' => "",
        'f' => "f",
        'l' => "l",
        _ => "f128",
    }
}

const STEMS: &[(&str, char)] = &[
    ("acos", '1'), ("acosh", '1'), ("asin", '1'), ("atanh", '1'), ("cosh", '1'), ("exp", '1'), ("exp10", '1'), ("exp2", '1'), ("j0", '1'), ("j1", '1'),
    ("lgamma", '1'), ("log", '1'), ("log10", '1'), ("log2", '1'), ("sinh", '1'), ("sqrt", '1'), ("tgamma", '1'), ("y0", '1'), ("y1", '1'),
    ("atan2", '2'), ("fmod", '2'), ("hypot", '2'), ("pow", '2'), ("remainder", '2'), ("scalb", '2'),
    ("jn", 'I'), ("yn", 'I'), ("lgamma_r", 'R'), ("gamma_r", 'R'),
];
const MODERN_RAW: &[(&str, char)] = &[("exp10", 'f'), ("remainder", 'd'), ("sqrt", 'f'), ("tgamma", 'f')];

fn stem_shape(stem: &str) -> char {
    STEMS.iter().find(|(s, _)| *s == stem).unwrap().1
}

pub fn split_name(name: &str) -> Option<(&'static str, char)> {
    for t in ['q', 'f', 'l', 'd'] {
        for (stem, shape) in STEMS {
            let s = if *shape == 'R' { format!("{}{}_r", &stem[..stem.len() - 2], suffix(t)) } else { format!("{stem}{}", suffix(t)) };
            if name == s {
                return Some((stem, t));
            }
        }
    }
    match name {
        "pow10" => Some(("exp10", 'd')),
        "pow10f" => Some(("exp10", 'f')),
        "pow10l" => Some(("exp10", 'l')),
        _ => None,
    }
}

fn target_of(stem: &str, t: char) -> String {
    if stem == "gamma_r" {
        return format!("tgamma{}", suffix(t));
    }
    if stem_shape(stem) == 'R' {
        return format!("{}{}_r", &stem[..stem.len() - 2], suffix(t));
    }
    format!("{stem}{}", suffix(t))
}

pub struct Entry {
    label: String,
    name: String,
    ver: String,
    stem: &'static str,
    t: char,
    finite: bool,
    shape: char,
    target: String,
}

pub fn entries(root: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in fs::read_to_string(root.join("tools/compat_symbols_libm.txt")).unwrap().lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let (name, ver, kind) = (f[0], f[1], f[2]);
        if kind != "func" || ["fromfp", "ufromfp", "totalorder", "matherr"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let finite = name.starts_with("__") && name.ends_with("_finite");
        let base = if finite { &name[2..name.len() - "_finite".len()] } else { name };
        let Some((stem, t)) = split_name(base) else { continue };
        if !finite && ver != "GLIBC_2.2.5" && ver != "GLIBC_2.23" {
            continue;
        }
        if !finite && t == 'q' {
            continue;
        }
        let label = format!("__rl_sv_{}_{}", name, ver.replace("GLIBC_", "").replace('.', "_"));
        out.push(Entry { label, name: name.into(), ver: ver.into(), stem, t, finite, shape: stem_shape(stem), target: target_of(stem, t) });
    }
    out
}

fn asm_sse(label: &str, target: &str, idx: usize, shape: char, t: char) -> Vec<String> {
    let mov = match t {
        'd' => "movsd",
        'f' => "movss",
        _ => "movups",
    };
    let q = |s: String| format!("    \"{s}\",");
    let mut l: Vec<String> = vec![
        "    \".pushsection .text.rl_compat,\\\"ax\\\",@progbits\",".into(),
        "    \".p2align 4\",".into(),
        q(format!(".globl {label}")),
        q(format!(".type {label}, @function")),
        q(format!("{label}:")),
        q("push rbx".into()),
        q("sub rsp, 64".into()),
        q(format!("{mov} [rsp], xmm0")),
    ];
    match shape {
        '2' => l.push(q(format!("{mov} [rsp+16], xmm1"))),
        'I' => {
            l.push(q("movsxd rax, edi".into()));
            l.push(q("mov [rsp+16], rax".into()));
        }
        'R' => l.push(q("mov [rsp+16], rdi".into())),
        _ => {}
    }
    l.push(q("mov rdi, rsp".into()));
    l.push(q(format!("mov esi, {idx}")));
    l.push(q("call __rl_sv_pre".into()));
    l.push(q(format!("{mov} xmm0, [rsp]")));
    match shape {
        '2' => l.push(q(format!("{mov} xmm1, [rsp+16]"))),
        'I' => l.push(q("mov edi, [rsp+16]".into())),
        'R' => l.push(q("mov rdi, [rsp+16]".into())),
        _ => {}
    }
    l.push(q(format!("call {target}")));
    l.push(q(format!("{mov} [rsp+32], xmm0")));
    l.push(q("mov rdi, rsp".into()));
    l.push(q(format!("mov esi, {idx}")));
    l.push(q("call __rl_sv_post".into()));
    l.push(q(format!("{mov} xmm0, [rsp+32]")));
    l.push(q("add rsp, 64".into()));
    l.push(q("pop rbx".into()));
    l.push(q("ret".into()));
    l.push(q(format!(".size {label}, .-{label}")));
    l.push("    \".popsection\",".into());
    l
}

fn asm_x87(label: &str, target: &str, idx: usize, shape: char) -> Vec<String> {
    let q = |s: String| format!("    \"{s}\",");
    let mut l: Vec<String> = vec![
        "    \".pushsection .text.rl_compat,\\\"ax\\\",@progbits\",".into(),
        "    \".p2align 4\",".into(),
        q(format!(".globl {label}")),
        q(format!(".type {label}, @function")),
        q(format!("{label}:")),
        q("push rbx".into()),
        q("sub rsp, 64".into()),
        q("fld tbyte ptr [rsp+80]".into()),
        q("fstp tbyte ptr [rsp]".into()),
    ];
    match shape {
        '2' => {
            l.push(q("fld tbyte ptr [rsp+96]".into()));
            l.push(q("fstp tbyte ptr [rsp+16]".into()));
        }
        'I' => {
            l.push(q("movsxd rax, edi".into()));
            l.push(q("mov [rsp+16], rax".into()));
        }
        'R' => l.push(q("mov [rsp+16], rdi".into())),
        _ => {}
    }
    for s in ["mov rdi, rsp".to_string(), format!("mov esi, {idx}"), "call __rl_sv_pre".into(), "sub rsp, 32".into(), "fld tbyte ptr [rsp+32]".into(), "fstp tbyte ptr [rsp]".into()] {
        l.push(q(s));
    }
    match shape {
        '2' => {
            l.push(q("fld tbyte ptr [rsp+48]".into()));
            l.push(q("fstp tbyte ptr [rsp+16]".into()));
        }
        'I' => l.push(q("mov edi, [rsp+48]".into())),
        'R' => l.push(q("mov rdi, [rsp+48]".into())),
        _ => {}
    }
    for s in [
        format!("call {target}"), "add rsp, 32".into(), "fstp tbyte ptr [rsp+32]".into(), "mov rdi, rsp".into(), format!("mov esi, {idx}"),
        "call __rl_sv_post".into(), "fld tbyte ptr [rsp+32]".into(), "add rsp, 64".into(), "pop rbx".into(), "ret".into(), format!(".size {label}, .-{label}"),
    ] {
        l.push(q(s));
    }
    l.push("    \".popsection\",".into());
    l
}

pub fn svid(root: &Path) {
    let ents = entries(root);
    let mut out: Vec<String> = vec![format!("pub static DESCS: [Desc; {}] = [", ents.len())];
    for e in &ents {
        let skip = !e.finite && MODERN_RAW.contains(&(e.stem, e.t));
        out.push(format!(
            "    Desc {{ stem: \"{}\", ty: Ty::{}, finite: {}, shape: b'{}', modern_raw: {} }},",
            e.stem, e.t.to_ascii_uppercase(), e.finite, e.shape, skip
        ));
    }
    out.push("];".into());
    out.push("".into());
    out.push("core::arch::global_asm!(".into());
    for (i, e) in ents.iter().enumerate() {
        out.extend(if e.t == 'l' { asm_x87(&e.label, &e.target, i, e.shape) } else { asm_sse(&e.label, &e.target, i, e.shape, e.t) });
    }
    out.push(");".into());
    fs::write(root.join("crates/rusty-libc-cabi/src/compat_svid_gen.rs"), out.join("\n") + "\n").unwrap();
    let mut raw: Vec<String> = vec!["pub static RAW: &[Raw] = &[".into()];
    if let Ok(t) = fs::read_to_string(root.join("tools/svid_raw_table.txt")) {
        for line in t.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            raw.push(format!("    Raw {{ name: \"{}\", ty: Ty::{}, errno: b'{}', nan: b'{}' }},", f[0], f[1].to_ascii_uppercase(), f[2], f[3]));
        }
    }
    raw.push("];".into());
    fs::write(root.join("crates/rusty-libc-cabi/src/compat_svid_raw.rs"), raw.join("\n") + "\n").unwrap();
    println!("{} old libm entries", ents.len());
}

const GROUPS: &[(&str, &[&str])] = &[
    ("rpc", &["xdr", "clnt", "svc", "auth", "_auth", "key_", "__key", "pmap", "rpc", "__rpc", "_rpc", "callrpc", "registerrpc", "get_myaddress", "getnetname", "getrpcport",
        "host2netname", "netname2", "user2netname", "rtime", "cbc_crypt", "ecb_crypt", "des_setparity", "passwd2des", "xdecrypt", "xencrypt", "getpublickey", "getsecretkey", "_seterr_reply", "xprt_"]),
    ("resolver", &["__res_", "__dn_", "ns_"]),
    ("pthread", &["pthread", "__pthread", "_pthread", "sem_", "cnd_", "mtx_", "thrd_", "tss_", "call_once", "sched_"]),
    ("dl", &["dl", "_dl_"]),
    ("aio", &["aio_", "lio_", "gai_", "getaddrinfo_a", "mq_", "__mq_", "timer_", "clock_", "shm_"]),
    ("string", &["__str", "__stp", "__mempcpy", "memcpy"]),
];

fn group_of(name: &str) -> &'static str {
    for (g, prefixes) in GROUPS {
        if prefixes.iter().any(|p| name.starts_with(p)) {
            return g;
        }
    }
    "misc"
}

const ZERO_DATA: &[&str] = &[
    "__after_morecore_hook", "__free_hook", "__malloc_hook", "__malloc_initialize_hook", "__memalign_hook", "__morecore", "__realloc_hook", "mallwatch",
    "_null_auth", "rpc_createerr", "svc_fdset", "svc_max_pollfd", "svc_pollfd", "svcauthdes_stats", "_obstack",
    "__key_decryptsession_pk_LOCAL", "__key_encryptsession_pk_LOCAL", "__key_gendes_LOCAL",
];
const TABLE_DATA: &[&str] = &["sys_errlist", "_sys_errlist", "sys_siglist", "_sys_siglist", "sys_sigabbrev", "sys_nerr", "_sys_nerr"];
const HAND_DATA: &[&str] = &["loc1", "loc2", "locs"];

extern "C" {
    fn dlvsym(handle: *mut std::ffi::c_void, symbol: *const std::ffi::c_char, version: *const std::ffi::c_char) -> *mut std::ffi::c_void;
}

fn glibc_table(name: &str, ver: &str, size: usize) -> Vec<u8> {
    let n = std::ffi::CString::new(name).unwrap();
    let v = std::ffi::CString::new(ver).unwrap();
    let addr = unsafe { dlvsym(std::ptr::null_mut(), n.as_ptr(), v.as_ptr()) };
    if addr.is_null() {
        panic!("dlvsym({name}, {ver}) failed");
    }
    unsafe { std::slice::from_raw_parts(addr as *const u8, size).to_vec() }
}

fn sym_head(out: &mut Vec<String>, label: &str, size: usize) {
    out.push(format!("        \".globl {label}\","));
    out.push(format!("        \".type {label}, @object\","));
    out.push(format!("        \".size {label}, {size}\","));
}

fn family(name: &str) -> &'static str {
    match name {
        "sys_errlist" | "_sys_errlist" => "errlist",
        "sys_siglist" | "_sys_siglist" => "siglist",
        _ => "sigabbrev",
    }
}

type Canon = BTreeMap<&'static str, Vec<(String, Vec<Option<String>>)>>;

fn data_block(name: &str, ver: &str, size: usize, label: &str, out: &mut Vec<String>, canon: &mut Canon) -> bool {
    if ZERO_DATA.contains(&name) {
        sym_head(out, label, size);
        out.push(format!("        \"{label}:\","));
        out.push(format!("        \".zero {size}\","));
        out.push(format!("        \".symver {label}, {name}@{ver}\","));
        return true;
    }
    if TABLE_DATA.contains(&name) {
        let raw = glibc_table(name, ver, size);
        if name == "sys_nerr" || name == "_sys_nerr" {
            sym_head(out, label, size);
            out.push(format!("        \"{label}:\","));
            out.push(format!("        \".long {}\",", i32::from_le_bytes(raw[..4].try_into().unwrap())));
            out.push(format!("        \".symver {label}, {name}@{ver}\","));
            return true;
        }
        let n = size / 8;
        let mut strs: Vec<Option<String>> = Vec::new();
        for i in 0..n {
            let p = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
            if p == 0 {
                strs.push(None);
            } else {
                let c = unsafe { std::ffi::CStr::from_ptr(p as *const std::ffi::c_char) };
                strs.push(Some(c.to_bytes().iter().map(|b| *b as char).collect()));
            }
        }
        let fam = family(name);
        if let Some(list) = canon.get(fam) {
            for (clabel, cstrs) in list {
                if cstrs.len() >= strs.len() && cstrs[..strs.len()] == strs[..] {
                    sym_head(out, label, size);
                    out.push(format!("        \".set {label}, {clabel}\","));
                    out.push(format!("        \".symver {label}, {name}@{ver}\","));
                    return true;
                }
            }
        }
        canon.entry(fam).or_default().push((label.to_string(), strs.clone()));
        sym_head(out, label, size);
        out.push("        \".p2align 3\",".into());
        out.push(format!("        \"{label}:\","));
        for (i, st) in strs.iter().enumerate() {
            out.push(format!("        \".quad {}\",", if st.is_some() { format!("{label}_s{i}") } else { "0".into() }));
        }
        out.push(format!("        \".symver {label}, {name}@{ver}\","));
        for (i, st) in strs.iter().enumerate() {
            if let Some(s) = st {
                let esc = s.replace('\\', "\\\\").replace('"', "\\\\\"");
                out.push(format!("        \"{label}_s{i}: .asciz \\\"{esc}\\\"\","));
            }
        }
        return true;
    }
    false
}

fn read_table(root: &Path, file: &str) -> Vec<(String, String, String, usize)> {
    let mut rows = Vec::new();
    for line in fs::read_to_string(root.join("tools").join(file)).unwrap().lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        rows.push((f[0].to_string(), f[1].to_string(), f[2].to_string(), f[3].parse().unwrap()));
    }
    rows
}

fn overrides(root: &Path) -> HashMap<(String, String), String> {
    let mut m: HashMap<(String, String), String> = HashMap::new();
    for (n, v, t) in OVERRIDES {
        m.insert((n.to_string(), v.to_string()), t.to_string());
    }
    if let Ok(t) = fs::read_to_string(root.join("tools/compat_overrides.txt")) {
        for line in t.lines() {
            let f: Vec<&str> = line.split('#').next().unwrap().split_whitespace().collect();
            if f.len() == 3 {
                m.insert((f[0].into(), f[1].into()), f[2].into());
            }
        }
    }
    m
}

pub fn compat_symver(root: &Path, defined: Option<&str>) {
    let ours: BTreeSet<String> = match defined {
        Some(f) => defined_from(f),
        None => {
            let a = std::env::var("COMPAT_LIBC_A").map(std::path::PathBuf::from).unwrap_or_else(|_| root.join("target/sysroot/lib/libc.a"));
            nm(&["-g", "--defined-only"], &a)
        }
    };
    let ov = overrides(root);
    let rows = read_table(root, "compat_symbols.txt");
    let mut skipped_data: Vec<String> = Vec::new();
    let mut skipped_missing: Vec<String> = Vec::new();
    let mut groups: BTreeMap<&str, Vec<(String, String, String)>> = BTreeMap::new();
    for (name, ver, kind, _) in &rows {
        if kind != "func" {
            skipped_data.push(format!("{name}@{ver}"));
            continue;
        }
        let target = ov.get(&(name.clone(), ver.clone())).cloned().unwrap_or_else(|| name.clone());
        if !ours.contains(&target) && !ov.contains_key(&(name.clone(), ver.clone())) {
            skipped_missing.push(format!("{name}@{ver}"));
            continue;
        }
        groups.entry(group_of(name)).or_default().push((name.clone(), ver.clone(), target));
    }
    let mut data_lines: Vec<String> = Vec::new();
    let mut done_data: Vec<String> = Vec::new();
    let mut canon: Canon = BTreeMap::new();
    let mut by_size: Vec<&(String, String, String, usize)> = rows.iter().collect();
    by_size.sort_by_key(|r| std::cmp::Reverse(r.3));
    for (name, ver, kind, size) in by_size {
        if kind != "data" || HAND_DATA.contains(&name.as_str()) {
            continue;
        }
        let label = format!("__rl_cd_{}_{}", name, ver.replace("GLIBC_", "").replace('.', "_"));
        let mut block = Vec::new();
        if data_block(name, ver, *size, &label, &mut block, &mut canon) {
            data_lines.extend(block);
            done_data.push(format!("{name}@{ver}"));
        }
    }
    let skipped_data: Vec<String> = skipped_data.into_iter().filter(|d| !HAND_DATA.contains(&d.split('@').next().unwrap()) && !done_data.contains(d)).collect();
    let mut out: Vec<String> = vec![
    ];
    for chunk in skipped_missing.chunks(6) {
        println!("  not provided: {}", chunk.join(" "));
    }
    println!("  data objects not provided: {}", skipped_data.join(" "));
    out.push("#![allow(missing_docs)]".into());
    out.push("".into());
    out.push("pub mod data {".into());
    out.push("    core::arch::global_asm!(".into());
    out.push("        \".pushsection .data.rl_compat,\\\"aw\\\",@progbits\",".into());
    out.extend(data_lines);
    out.push("        \".popsection\",".into());
    out.push("    );".into());
    out.push("}".into());
    out.push("".into());
    let mut total = 0;
    for (g, list) in &groups {
        out.push(format!("pub mod {g} {{"));
        out.push("    core::arch::global_asm!(".into());
        out.push("        \".pushsection .text.rl_compat,\\\"ax\\\",@progbits\",".into());
        for (name, ver, target) in list {
            let label = format!("__rl_cs_{}_{}", name, ver.replace("GLIBC_", "").replace('.', "_"));
            out.push("        \".p2align 3\",".into());
            out.push(format!("        \".globl {label}\","));
            out.push(format!("        \"{label}:\","));
            out.push(format!("        \"jmp {target}\","));
            out.push(format!("        \".symver {label}, {name}@{ver}\","));
            total += 1;
        }
        out.push("        \".popsection\",".into());
        out.push("    );".into());
        out.push("}".into());
        out.push("".into());
    }
    fs::write(root.join("crates/rusty-libc-cabi/src/compat_symver.rs"), out.join("\n")).unwrap();
    println!(
        "{} versioned function symbols in {} groups, {} data objects; {} functions skipped (not defined), {} data objects skipped",
        total, groups.len(), done_data.len(), skipped_missing.len(), skipped_data.len()
    );
}

const OLDFP_SUFFIX: &[(&str, char)] = &[("", 'd'), ("f", 'f'), ("l", 'l'), ("f32", 'f'), ("f64", 'd'), ("f32x", 'd'), ("f64x", 'l'), ("f128", 'q')];
const OLDFP_BASES: &[(&str, &str)] = &[("ufromfpx", "ofp3"), ("fromfpx", "ofp2"), ("ufromfp", "ofp1"), ("fromfp", "ofp0"), ("totalordermag", "otm"), ("totalorder", "oto")];

fn oldfp_target(name: &str) -> Option<String> {
    for (base, kind) in OLDFP_BASES {
        if let Some(rest) = name.strip_prefix(base) {
            if let Some((_, t)) = OLDFP_SUFFIX.iter().find(|(s, _)| *s == rest) {
                return Some(if kind.starts_with("ofp") { format!("__rl_ofp_{}{}", t, &kind[3..]) } else { format!("__rl_{kind}_{t}") });
            }
        }
    }
    None
}

pub fn compat_symver_math(root: &Path, defined: Option<&str>) {
    let svid: HashMap<(String, String), String> = entries(root).into_iter().map(|e| ((e.name, e.ver), e.label)).collect();
    let ours: BTreeSet<String> = match defined {
        Some(f) => defined_from(f),
        None => {
            let a = std::env::var("COMPAT_LIBC_A").map(std::path::PathBuf::from).unwrap_or_else(|_| root.join("target/sysroot/lib/libc.a"));
            nm(&["-g", "--defined-only"], &a)
        }
    };
    let math_target = |n: &str, v: &str| -> Option<&'static str> {
        match (n, v) {
            ("pow10", "GLIBC_2.2.5") => Some("exp10"),
            ("pow10f", "GLIBC_2.2.5") => Some("exp10f"),
            ("pow10l", "GLIBC_2.2.5") => Some("exp10l"),
            ("matherr", "GLIBC_2.2.5") => Some("__rl_old_matherr"),
            _ => None,
        }
    };
    let finite_target = |b: &str| -> String {
        match b {
            "gamma_r" => "lgamma_r".into(),
            "gammaf_r" => "lgammaf_r".into(),
            "gammal_r" => "lgammal_r".into(),
            "gammaf128_r" => "lgammaf128_r".into(),
            _ => b.to_string(),
        }
    };
    let (mut funcs, mut data, mut skipped): (Vec<(String, String, String)>, Vec<(String, String, usize)>, Vec<String>) = (vec![], vec![], vec![]);
    for (name, ver, kind, size) in read_table(root, "compat_symbols_libm.txt") {
        if kind == "data" {
            if name == "_LIB_VERSION" {
                data.push((name, ver, size));
            } else {
                skipped.push(format!("{name}@{ver}"));
            }
            continue;
        }
        let mut target: Option<String> = svid.get(&(name.clone(), ver.clone())).cloned().or_else(|| math_target(&name, &ver).map(String::from));
        if target.is_none() && ["GLIBC_2.25", "GLIBC_2.26", "GLIBC_2.27"].contains(&ver.as_str()) {
            target = oldfp_target(&name);
        }
        if target.is_none() && name.starts_with("__") && name.ends_with("_finite") {
            target = Some(finite_target(&name[2..name.len() - "_finite".len()]));
        }
        let target = target.unwrap_or_else(|| name.clone());
        if !ours.contains(&target) && !target.starts_with("__rl_") {
            skipped.push(format!("{name}@{ver}"));
            continue;
        }
        funcs.push((name, ver, target));
    }
    let mut out: Vec<String> = vec![
        "#![allow(missing_docs)]".into(),
        "".into(),
        "core::arch::global_asm!(".into(),
        "    \".pushsection .data.rl_compat,\\\"aw\\\",@progbits\",".into(),
    ];
    for (name, ver, size) in &data {
        let label = format!("__rl_cd_{}_{}", name, ver.replace("GLIBC_", "").replace('.', "_"));
        out.push(format!("    \".globl {label}\","));
        out.push(format!("    \".type {label}, @object\","));
        out.push(format!("    \".size {label}, {size}\","));
        out.push("    \".p2align 2\",".into());
        out.push(format!("    \"{label}:\","));
        out.push("    \".long 2\",".into());
        if *size > 4 {
            out.push(format!("    \".zero {}\",", size - 4));
        }
        out.push(format!("    \".symver {label}, {name}@{ver}\","));
    }
    out.push("    \".popsection\",".into());
    out.push("    \".pushsection .text.rl_compat,\\\"ax\\\",@progbits\",".into());
    for (name, target) in [("__clog10", "clog10"), ("__clog10f", "clog10f")] {
        out.push("    \".p2align 3\",".into());
        out.push(format!("    \".globl {name}\","));
        out.push(format!("    \".type {name}, @function\","));
        out.push(format!("    \"{name}:\","));
        out.push(format!("    \"jmp {target}\","));
    }
    for (name, ver, target) in &funcs {
        let label = format!("__rl_cs_{}_{}", name, ver.replace("GLIBC_", "").replace('.', "_"));
        out.push("    \".p2align 3\",".into());
        out.push(format!("    \".globl {label}\","));
        out.push(format!("    \"{label}:\","));
        out.push(format!("    \"jmp {target}\","));
        out.push(format!("    \".symver {label}, {name}@{ver}\","));
    }
    out.push("    \".popsection\",".into());
    out.push(");".into());
    fs::write(root.join("crates/rusty-libc-cabi/src/compat_symver_math.rs"), out.join("\n") + "\n").unwrap();
    println!("math: {} versioned function symbols, {} data objects, {} skipped", funcs.len(), data.len(), skipped.len());
}
